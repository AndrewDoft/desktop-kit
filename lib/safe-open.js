"use strict";
// The one door to the system browser. A URL that came from a server, a config
// file or the renderer must not reach shell.openExternal as file:, smb:, a
// custom protocol handler, etc.: https is always fine, http only to this
// machine. `extraHosts` widens the http allow-list per app.

const LOOPBACK = ["localhost", "127.0.0.1", "[::1]"];

function isSafeUrl(raw, extraHosts = []) {
  let u;
  try {
    u = new URL(String(raw));
  } catch {
    return false;
  }
  return u.protocol === "https:" || (u.protocol === "http:" && [...LOOPBACK, ...extraHosts].includes(u.hostname));
}

/** Resolves to what shell.openExternal resolves to; rejects for a refused URL. */
function openSafe(url, shell = require("electron").shell, extraHosts = []) {
  if (!isSafeUrl(url, extraHosts)) return Promise.reject(new Error(`refusing to open ${String(url).slice(0, 80)}`));
  return Promise.resolve(shell.openExternal(String(url)));
}

module.exports = { isSafeUrl, openSafe };
