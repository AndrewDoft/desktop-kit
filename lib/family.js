"use strict";
// The Masora family (Masora, Zevet, Zevet Voice) senses and pairs with each other on one
// machine through a per-user directory of small files. This module is the part every
// Electron member does the same way; the on-disk format is what shipped apps already
// write, so old and new builds keep pairing.
//
//   <dir>/masora.json         {app, runtime:"masora-desktop", web, api, version, pid, updated_at}  Masora writes
//   <dir>/family.key          the pairing secret: 32 random bytes as 64 hex chars, user-only        Masora writes
//   <dir>/<app>.json          heartbeat {app, version, pid, updated_at, running, install_path,
//                             masora:{connected, member_email}} every 60 s (zevet, voice)           the app writes
//   <dir>/<app>.request.json  {action, requested_by?, at?, ...} a sibling asks <app> to act;
//                             <app> reads it, DELETES it, then acts                                 others write
//
// Files are replaced atomically (`<file>.tmp` then rename). Voice (Python) keeps its own
// reader of the same files: zevet-voice/masora_dictation/family.py (family_dir, _read, _write,
// beat, handle_request, pair's `family.key` read).
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const crypto = require("node:crypto");
const { spawnSync } = require("node:child_process");

const KEY_FILE = "family.key";
const MANIFEST_FILE = "masora.json";
const KEY_BYTES = 32;
/** A sibling rewrites its heartbeat every 60 s; three missed beats is a dead app. */
const STALE_MS = 3 * 60 * 1000;

/** MASORA_FAMILY_DIR overrides; else one per-OS path per user (Windows %LOCALAPPDATA%\Masora\family,
 *  macOS ~/Library/Application Support/Masora/family, elsewhere ~/.local/share/masora/family — the
 *  path packages/core/core/family.py, the key's writer, uses). */
function familyDir(env = process.env, platform = process.platform, home = os.homedir()) {
  if (env.MASORA_FAMILY_DIR) return env.MASORA_FAMILY_DIR;
  if (platform === "win32") return path.join(env.LOCALAPPDATA || path.join(home, "AppData", "Local"), "Masora", "family");
  if (platform === "darwin") return path.join(home, "Library", "Application Support", "Masora", "family");
  return path.join(home, ".local", "share", "masora", "family");
}

/** A JSON object from `file`, or null (absent, unreadable, not JSON, or not an object). */
function readJson(file) {
  try {
    const v = JSON.parse(fs.readFileSync(file, "utf8"));
    return v && typeof v === "object" && !Array.isArray(v) ? v : null;
  } catch {
    return null;
  }
}

/** Write JSON to `<file>.tmp`, then rename over `file`. Creates the directory. Throws on failure. */
function writeJsonAtomic(file, value) {
  fs.mkdirSync(path.dirname(file), { recursive: true });
  const tmp = `${file}.tmp`;
  fs.writeFileSync(tmp, JSON.stringify(value));
  fs.renameSync(tmp, file);
}

/** The pairing secret, trimmed, or null when Masora has not written one. */
function readKey(dir) {
  try {
    return fs.readFileSync(path.join(dir, KEY_FILE), "utf8").trim() || null;
  } catch {
    return null;
  }
}

/** POSIX 0600; on Windows drop inherited ACEs and grant only the current user (icacls ships with
 *  Windows). Throws when it cannot: a key that could not be restricted must not be handed out. */
function restrictToCurrentUser(file, platform = process.platform) {
  if (platform !== "win32") {
    fs.chmodSync(file, 0o600);
    return;
  }
  const domain = process.env.USERDOMAIN;
  const name = os.userInfo().username;
  const r = spawnSync("icacls", [file, "/inheritance:r", "/grant:r", `${domain ? `${domain}\\` : ""}${name}:(R,W,D)`], { encoding: "utf8", timeout: 30000, windowsHide: true });
  if (r.status !== 0) throw new Error(`icacls failed (${r.status}) on ${path.basename(file)}: ${(r.stdout || r.stderr || "").trim()}`);
}

/** Create-once: a well-formed existing key (64 chars) is returned untouched. A new one is 32 random
 *  bytes as hex, the file created EMPTY and restricted before the secret lands. `restrict` is
 *  injectable for tests. (Masora's runtime is the writer of this file today; a member that finds
 *  none must not invent a second format.) */
function ensureKey(dir, { restrict = restrictToCurrentUser } = {}) {
  const have = readKey(dir);
  if (have && have.length === KEY_BYTES * 2) return have;
  fs.mkdirSync(dir, { recursive: true });
  const file = path.join(dir, KEY_FILE);
  const key = crypto.randomBytes(KEY_BYTES).toString("hex");
  fs.writeFileSync(file, "", "ascii");
  restrict(file);
  fs.writeFileSync(file, key, "ascii");
  return key;
}

/** The web origin (no trailing slash) Masora published in masora.json, or "" unless it is the
 *  desktop runtime. Whether it actually answers is the caller's /healthz check. */
function masoraWeb(dir) {
  const m = readJson(path.join(dir, MANIFEST_FILE));
  return m && m.runtime === "masora-desktop" && typeof m.web === "string" ? m.web.replace(/\/+$/, "") : "";
}

/** Write `<app>.json` (the heartbeat) atomically; throws on failure. `body` is the app's own record. */
function writeHeartbeat(dir, app, body) {
  writeJsonAtomic(path.join(dir, `${app}.json`), body);
}

/** A sibling's heartbeat record, or null when it has never written one. */
function readHeartbeat(dir, app) {
  return readJson(path.join(dir, `${app}.json`));
}

/** Is this heartbeat a running app: not explicitly `running:false`, with a parseable `updated_at`
 *  newer than STALE_MS. (A file outlives a crash; a clean exit writes running:false.) */
function isRunning(record, now = Date.now(), staleMs = STALE_MS) {
  const beat = record && Date.parse(record.updated_at);
  return !!(record && record.running !== false && beat && now - beat < staleMs);
}

/** Ask `<app>` to act: `<app>.request.json`, atomically. `body` is written as given (callers add
 *  requested_by/at). Throws on failure. */
function writeRequest(dir, app, body) {
  writeJsonAtomic(path.join(dir, `${app}.request.json`), body);
}

/** Take (read then delete) the request addressed to `<app>`. Null when there is none, or when it
 *  cannot be deleted — a request that cannot be removed cannot be promised to run only once. */
function takeRequest(dir, app) {
  const file = path.join(dir, `${app}.request.json`);
  const req = readJson(file);
  if (!req) return null;
  try {
    fs.rmSync(file, { force: true });
  } catch {
    return null;
  }
  return req;
}

module.exports = {
  KEY_FILE, MANIFEST_FILE, STALE_MS,
  familyDir, readJson, writeJsonAtomic, readKey, ensureKey, restrictToCurrentUser, masoraWeb,
  writeHeartbeat, readHeartbeat, isRunning, writeRequest, takeRequest,
};
