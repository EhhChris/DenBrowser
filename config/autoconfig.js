// autoconfig.js — installed to <app>/defaults/pref/autoconfig.js in dev builds
// Instructs Firefox to load mozilla.cfg from the application directory.
// pref() here configures the autoconfig system itself; these are not lockable.
pref("general.config.filename", "mozilla.cfg");
pref("general.config.obscure_value", 0);
