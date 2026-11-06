//! `${NAME}` environment-variable references in config string values.
//!
//! Expansion runs on the *parsed* TOML tree, never on the file's text.  A
//! variable's value is therefore always data: quotes, backslashes, or newlines
//! in it cannot change the file's structure (a Windows path needs no TOML
//! escaping), and references in comments or keys are never looked at.
//!
//! The syntax is deliberately narrow:
//!
//! - `${NAME}` is replaced by the variable's value.  `NAME` is ASCII letters,
//!   digits, and `_`, not starting with a digit.  On Windows the lookup ignores
//!   case, as Windows itself does, so `${path}` finds `PATH`.
//! - `$${` is a literal `${`.  More generally, in a run of `$` directly before
//!   a `{`, each `$$` is one literal `$`, and an odd `$` left over opens a
//!   reference — so `$$${NAME}` is a `$` followed by the value.
//! - Every other `$` is literal.  Bare `$NAME` is *not* a reference, so a value
//!   such as `pa$$word` or `$HOME/x` keeps the meaning it had before expansion
//!   existed; only text containing `${` can read differently.
//! - The value is inserted as-is and is not scanned again.  It always fills one
//!   string: a variable cannot supply several entries of a list.
//!
//! An error stops startup when a variable is unset, empty, or not valid
//! Unicode, when its value begins or ends with whitespace or an invisible
//! character, and when a reference is malformed (such as `${NAME:-default}`):
//!
//! - Empty: an empty `upstream_ca` and a blank `[logging].dir` both mean "off",
//!   so a variable that quietly expanded to nothing could weaken the proxy
//!   instead of stopping it.  A setting meant to be empty is written as `""` in
//!   the file.
//! - Padding: whitespace or an invisible character at either end is nearly
//!   always an accident, typically the trailing newline or byte-order mark of
//!   a file the value was read from, and no consumer can tell it from intent.
//!   A padded rate-limit glob compiles but never matches, and a padded entry
//!   in a log directive list (`"${LEVEL},foo=debug"`) silences logging.  A
//!   value that really does begin or end with a space, such as a passphrase,
//!   has to be written in the file instead.
//!
//! References are resolved in every section, including one switched off with
//! `enabled = false`, so a disabled section still needs its variables set.
//!
//! Only TOML strings are expanded.  A number or boolean cannot hold a
//! reference, and quoting one (`max_requests = "${MAX}"`) is rejected as the
//! wrong type before expansion runs.
//!
//! Errors never quote a value or the text around a reference.  They name the
//! setting and, outside the secret settings the caller lists, the variable.  In
//! a secret setting the variable is not named either, because the text between
//! `${` and `}` may be part of an inline secret rather than a reference.

use std::env::VarError;

/// Resolves a variable name to its value; `std::env::var` in production.
pub(super) type Lookup<'a> = dyn Fn(&str) -> Result<String, VarError> + 'a;

/// Expand every string value in `table`, including those inside arrays and
/// arrays of tables.
///
/// Every failing setting is reported, not only the first, so one failed start
/// shows everything that needs fixing.  `secrets` lists the settings, by the
/// path errors print, whose errors must not name the variable.
pub(super) fn expand(
    table: &mut toml::Table,
    lookup: &Lookup<'_>,
    secrets: &[&str],
) -> anyhow::Result<()> {
    let mut errors = Vec::new();
    for (key, value) in table.iter_mut() {
        expand_value(value, &format!("[{key}]"), lookup, secrets, &mut errors);
    }
    if errors.is_empty() {
        Ok(())
    } else {
        Err(anyhow::anyhow!(errors.join("; ")))
    }
}

/// `path` is the setting's name as the other config errors print it:
/// `[proxy].tls_cert`, `[rate_limiting].rules[0].pattern`.
fn expand_value(
    value: &mut toml::Value,
    path: &str,
    lookup: &Lookup<'_>,
    secrets: &[&str],
    errors: &mut Vec<String>,
) {
    match value {
        toml::Value::String(s) => match expand_str(s, lookup, secrets.contains(&path)) {
            Ok(expanded) => *s = expanded,
            Err(e) => errors.push(format!("{path}: {e}")),
        },
        toml::Value::Array(items) => {
            for (i, item) in items.iter_mut().enumerate() {
                expand_value(item, &format!("{path}[{i}]"), lookup, secrets, errors);
            }
        }
        toml::Value::Table(table) => {
            for (key, item) in table.iter_mut() {
                expand_value(item, &format!("{path}.{key}"), lookup, secrets, errors);
            }
        }
        toml::Value::Integer(_)
        | toml::Value::Float(_)
        | toml::Value::Boolean(_)
        | toml::Value::Datetime(_) => {}
    }
}

/// Expand the references in one string.  `secret` withholds the variable's
/// name from any error.
fn expand_str(s: &str, lookup: &Lookup<'_>, secret: bool) -> Result<String, String> {
    let var = |name: &str| {
        if secret {
            "a referenced environment variable".to_owned()
        } else {
            format!("environment variable `{name}`")
        }
    };

    let mut out = String::with_capacity(s.len());
    let mut rest = s;
    while let Some(start) = rest.find('$') {
        out.push_str(&rest[..start]);
        let run = rest[start..].bytes().take_while(|&b| b == b'$').count();
        let after = &rest[start + run..];

        // Away from a `{`, every `$` is literal.
        let Some(body) = after.strip_prefix('{') else {
            out.push_str(&"$".repeat(run));
            rest = after;
            continue;
        };

        // Before one, pairs are escaped dollars.  An even run leaves the `{`
        // as ordinary text, which the next pass of the loop copies through.
        out.push_str(&"$".repeat(run / 2));
        if run % 2 == 0 {
            rest = after;
            continue;
        }

        let end = body
            .find('}')
            .ok_or("unterminated `${` (write `$${` for a literal `${`)")?;
        let name = &body[..end];
        if !is_valid_name(name) {
            // Never quoted back, in any setting: text that is not a valid
            // name is the likeliest to be a secret that happens to contain `${`.
            return Err(
                "invalid `${...}` reference: a variable name is ASCII letters, \
                 digits and `_`, not starting with a digit, and `${NAME:-default}` \
                 forms are not supported (write `$${` for a literal `${`)"
                    .to_owned(),
            );
        }
        match lookup(name) {
            Ok(value) if value.chars().all(is_padding) => {
                return Err(format!(
                    "{} is empty or only whitespace or invisible characters",
                    var(name)
                ));
            }
            Ok(value) if value.starts_with(is_padding) || value.ends_with(is_padding) => {
                return Err(format!(
                    "{} begins or ends with whitespace or an invisible character, such as \
                     the trailing newline or byte-order mark of a file it was read from",
                    var(name)
                ));
            }
            Ok(value) => out.push_str(&value),
            Err(VarError::NotPresent) => return Err(format!("{} is not set", var(name))),
            Err(VarError::NotUnicode(_)) => {
                return Err(format!("{} is not valid Unicode", var(name)));
            }
        }
        rest = &body[end + 1..];
    }
    out.push_str(rest);
    Ok(out)
}

/// Characters that are not allowed at either end of a value: Unicode
/// whitespace, plus the invisible format characters `str::trim` leaves alone.
/// U+FEFF is the byte-order mark an editor may put at the start of a file.
fn is_padding(c: char) -> bool {
    c.is_whitespace()
        || matches!(
            c,
            '\u{FEFF}' | '\u{200B}' | '\u{200C}' | '\u{200D}' | '\u{2060}' | '\u{180E}'
        )
}

fn is_valid_name(name: &str) -> bool {
    let mut chars = name.chars();
    chars
        .next()
        .is_some_and(|c| c.is_ascii_alphabetic() || c == '_')
        && chars.all(|c| c.is_ascii_alphanumeric() || c == '_')
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::ffi::OsString;

    /// A lookup over a fixed set of variables, so tests never touch (or
    /// depend on) the real process environment.
    fn vars(pairs: &[(&str, &str)]) -> impl Fn(&str) -> Result<String, VarError> {
        let map: std::collections::HashMap<String, String> = pairs
            .iter()
            .map(|(k, v)| ((*k).to_owned(), (*v).to_owned()))
            .collect();
        move |name| map.get(name).cloned().ok_or(VarError::NotPresent)
    }

    fn expand_with(s: &str, pairs: &[(&str, &str)]) -> Result<String, String> {
        expand_str(s, &vars(pairs), false)
    }

    #[test]
    fn replaces_references_anywhere_in_the_string() {
        let env = [("HOST", "backend.internal"), ("PORT", "443")];
        assert_eq!(expand_with("${HOST}", &env).unwrap(), "backend.internal");
        assert_eq!(
            expand_with("${HOST}:${PORT}", &env).unwrap(),
            "backend.internal:443"
        );
        assert_eq!(
            expand_with("/etc/${HOST}/tls.crt", &env).unwrap(),
            "/etc/backend.internal/tls.crt"
        );
        assert_eq!(
            expand_with("${HOST}${PORT}", &env).unwrap(),
            "backend.internal443"
        );
    }

    #[test]
    fn names_may_use_underscores_digits_and_either_case() {
        let env = [("_a1", "x"), ("Proxy_TLS_2", "y")];
        assert_eq!(expand_with("${_a1}-${Proxy_TLS_2}", &env).unwrap(), "x-y");
    }

    #[test]
    fn strings_without_a_reference_are_unchanged() {
        // Every `$` that does not precede a `{` is literal, so values written
        // before expansion existed keep their meaning.
        for s in [
            "",
            "plain",
            "pa$$word",
            "$HOME/certs",
            "5$",
            "$",
            "$$",
            "a}b",
            "{x}",
        ] {
            assert_eq!(expand_with(s, &[]).unwrap(), s);
        }
    }

    #[test]
    fn doubled_dollars_before_a_brace_are_literal() {
        let env = [("X", "val")];
        assert_eq!(expand_with("$${X}", &env).unwrap(), "${X}");
        assert_eq!(expand_with("$$${X}", &env).unwrap(), "$val");
        assert_eq!(expand_with("$$$${X}", &env).unwrap(), "$${X}");
        // The escape needs no variable to exist.
        assert_eq!(expand_with("$${MISSING}", &[]).unwrap(), "${MISSING}");
    }

    #[test]
    fn values_are_inserted_verbatim_and_not_expanded_again() {
        let env = [
            ("OUTER", "${INNER}"),
            ("INNER", "never"),
            ("WIN", r"C:\certs\a.pem"),
            ("INSIDE", "C:/Program Files/a b.pem"),
        ];
        assert_eq!(expand_with("${OUTER}", &env).unwrap(), "${INNER}");
        assert_eq!(expand_with("${WIN}", &env).unwrap(), r"C:\certs\a.pem");
        // Whitespace inside a value is ordinary content.
        assert_eq!(
            expand_with("${INSIDE}", &env).unwrap(),
            "C:/Program Files/a b.pem"
        );
    }

    #[test]
    fn values_with_surrounding_padding_are_errors() {
        // Neither trimmed nor kept: `example.com\n` or a byte-order mark in a
        // glob would never match.
        for padded in [
            "info\n",
            "info\r\n",
            " info",
            "info ",
            "\tinfo",
            "\u{FEFF}example.com/*",
            "example.com/*\u{200B}",
            "\u{2060}info",
        ] {
            let error = expand_with("${PADDED}", &[("PADDED", padded)]).unwrap_err();
            assert!(
                error.starts_with(
                    "environment variable `PADDED` begins or ends with whitespace or an \
                     invisible character"
                ),
                "{padded:?} got: {error}"
            );
        }
        // Inside a value they are ordinary content.
        assert_eq!(
            expand_with("${X}", &[("X", "a\u{200B}b")]).unwrap(),
            "a\u{200B}b"
        );
        // Text around the reference may carry whitespace; only the value is checked.
        assert_eq!(expand_with(" ${X} ", &[("X", "info")]).unwrap(), " info ");
    }

    #[test]
    fn unset_blank_and_non_unicode_variables_are_errors() {
        let error = expand_with("${MISSING}", &[]).unwrap_err();
        assert_eq!(error, "environment variable `MISSING` is not set");

        // Blank counts as empty: `[logging].dir` treats " " as "no log file",
        // so it must not get through where "" would not.
        for blank in ["", " ", "\n", " \t\r\n", "\u{200B}", "\u{FEFF}\n"] {
            let error = expand_with("${BLANK}", &[("BLANK", blank)]).unwrap_err();
            assert_eq!(
                error,
                "environment variable `BLANK` is empty or only whitespace or invisible \
                 characters",
                "{blank:?}"
            );
        }

        let not_unicode = |_: &str| Err(VarError::NotUnicode(OsString::from("x")));
        let error = expand_str("${BYTES}", &not_unicode, false).unwrap_err();
        assert_eq!(error, "environment variable `BYTES` is not valid Unicode");
    }

    #[test]
    fn malformed_references_are_errors() {
        let env = [("X", "val")];
        for s in ["${", "${X", "a${X", "${}"] {
            assert!(expand_with(s, &env).is_err(), "{s:?} should be rejected");
        }
        for s in [
            "${1X}", "${X:-d}", "${X-d}", "${X Y}", "${ X}", "${é}", "${X.Y}",
        ] {
            let error = expand_with(s, &env).unwrap_err();
            assert!(
                error.contains("invalid `${...}` reference"),
                "{s:?} got: {error}"
            );
        }
    }

    #[test]
    fn errors_never_contain_a_value() {
        // A later failure in the same string must not echo what an earlier
        // reference expanded to, nor the literal text around it.
        let env = [("SECRET", "hunter2")];
        let error = expand_with("pre-${SECRET}-${MISSING}", &env).unwrap_err();
        assert!(!error.contains("hunter2"), "value leaked: {error}");
        assert!(!error.contains("pre-"), "literal text leaked: {error}");

        let error = expand_with("hunter2${hunter3:-x}", &[]).unwrap_err();
        assert!(!error.contains("hunter"), "secret text leaked: {error}");
    }

    #[test]
    fn secret_settings_withhold_the_variable_name() {
        // An inline passphrase that happens to contain `${...}` with a valid
        // name: the "name" is part of the secret, so it is not printed.
        let mut table: toml::Table =
            toml::from_str("[proxy]\ntls_key_passphrase = 'Tr0ub${xY9zQ}or'\n").unwrap();
        let error = expand(&mut table, &vars(&[]), &["[proxy].tls_key_passphrase"])
            .unwrap_err()
            .to_string();
        assert_eq!(
            error,
            "[proxy].tls_key_passphrase: a referenced environment variable is not set"
        );

        let error = expand_str("${xY9zQ}", &vars(&[("xY9zQ", " ")]), true).unwrap_err();
        assert!(!error.contains("xY9zQ"), "got: {error}");
    }

    fn all_errors(toml: &str) -> String {
        let mut table: toml::Table = toml::from_str(toml).unwrap();
        expand(&mut table, &vars(&[]), &[]).unwrap_err().to_string()
    }

    #[test]
    fn errors_name_the_setting_by_its_path() {
        let error = all_errors("[proxy]\ntls_cert = \"${MISSING}\"\n");
        assert_eq!(
            error,
            "[proxy].tls_cert: environment variable `MISSING` is not set"
        );

        let error = all_errors(
            "[machine_identity]\nallowed_hostnames = [\"ws-*.example.com\", \"${MISSING}\"]\n",
        );
        assert!(
            error.starts_with("[machine_identity].allowed_hostnames[1]: "),
            "got: {error}"
        );

        let error = all_errors(
            r#"
            [[rate_limiting.rules]]
            pattern = "example.com/*"

            [[rate_limiting.rules]]
            pattern = "${MISSING}"
            "#,
        );
        assert!(
            error.starts_with("[rate_limiting].rules[1].pattern: "),
            "got: {error}"
        );
    }

    #[test]
    fn every_failing_setting_is_reported() {
        let error = all_errors(
            r#"
            [proxy]
            tls_cert = "${CERT}"
            tls_key = "${KEY}"

            [logging]
            dir = "${LOG_DIR}"
            "#,
        );
        for part in [
            "[proxy].tls_cert: environment variable `CERT` is not set",
            "[proxy].tls_key: environment variable `KEY` is not set",
            "[logging].dir: environment variable `LOG_DIR` is not set",
        ] {
            assert!(error.contains(part), "missing {part:?} in: {error}");
        }
        assert_eq!(error.matches("; ").count(), 2, "got: {error}");
    }
}
