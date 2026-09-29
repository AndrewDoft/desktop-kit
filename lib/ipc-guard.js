"use strict";
// Who may call the privileged IPC bridge. A window that loads a remote origin
// with a preload attached makes every handler reachable from whatever that page
// runs; a call is honoured only from an allowed origin or an allowed local file.
const { fileURLToPath } = require("node:url");
const path = require("node:path");

/**
 * Is a frame at `frameUrl` allowed?
 *  origins  — http(s) URLs whose origin is allowed; falsy entries are ignored
 *  files    — absolute paths of the app's own pages (exact match)
 *  anyFile  — any file: URL (weaker; for shells that only ever load their own files)
 */
function senderAllowed(frameUrl, { origins = [], files = [], anyFile = false } = {}) {
  let u;
  try {
    u = new URL(String(frameUrl));
  } catch {
    return false;
  }
  if (u.protocol === "file:") {
    if (anyFile) return true;
    try {
      const p = path.resolve(fileURLToPath(u));
      return files.some((f) => path.resolve(f) === p);
    } catch {
      return false;
    }
  }
  if (u.origin === "null") return false;
  return origins.some((o) => {
    try {
      return !!o && new URL(o).origin === u.origin;
    } catch {
      return false;
    }
  });
}

/** Patch `ipcMain.handle` so every later registration checks its sender first.
 *  `policy()` returns the senderAllowed options at call time (origins can change).
 *  `denied(channel)` supplies the reply for a refused call; default throws. */
function guardIpc(ipcMain, policy, denied = (channel) => { throw new Error(`ipc ${channel}: sender not allowed`); }) {
  const handle = ipcMain.handle.bind(ipcMain);
  ipcMain.handle = (channel, fn) =>
    handle(channel, (event, ...args) =>
      senderAllowed(event && event.senderFrame && event.senderFrame.url, policy()) ? fn(event, ...args) : denied(channel));
}

module.exports = { senderAllowed, guardIpc };
