"use strict";
const { test } = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const kit = require("..");

const GOLDEN = path.join(__dirname, "fixtures", "family");
/** A family dir written in today's format: masora.json + family.key as Masora's runtime (Python) writes
 *  them, zevet.json as Zevet writes it, voice.json as Voice (indent=1) writes it, and two request files. */
function copyGolden() {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "kit-family-"));
  for (const f of fs.readdirSync(GOLDEN)) fs.copyFileSync(path.join(GOLDEN, f), path.join(dir, f));
  return dir;
}
const bytes = (f) => fs.readFileSync(path.join(GOLDEN, f), "utf8");

test("familyDir: override, Windows, macOS, elsewhere (the paths shipped apps use)", () => {
  assert.equal(kit.familyDir({ MASORA_FAMILY_DIR: "/x" }, "win32", "/h"), "/x");
  assert.equal(kit.familyDir({ LOCALAPPDATA: "C:\\L" }, "win32", "/h"), path.join("C:\\L", "Masora", "family"));
  assert.equal(kit.familyDir({}, "win32", path.join("/h")), path.join("/h", "AppData", "Local", "Masora", "family"));
  assert.equal(kit.familyDir({}, "darwin", "/Users/u"), path.join("/Users/u", "Library", "Application Support", "Masora", "family"));
  assert.equal(kit.familyDir({}, "linux", "/home/u"), path.join("/home/u", ".local", "share", "masora", "family"));
});

test("golden: today's family dir is read as the apps read it", () => {
  const dir = copyGolden();
  assert.equal(kit.masoraWeb(dir), "http://127.0.0.1:3210");
  assert.equal(kit.readKey(dir), bytes("family.key"));
  assert.equal(kit.readKey(dir).length, 64);
  const z = kit.readHeartbeat(dir, "zevet");
  assert.equal(z.version, "0.2.86");
  assert.equal(z.masora.member_email, "a@b.co");
  assert.equal(z.team_name, "acme");
  const v = kit.readHeartbeat(dir, "voice");
  assert.equal(v.masora.connected, false);
  assert.equal(v.masora.member_email, null);
  const at = Date.parse("2026-09-29T04:00:00Z");
  assert.equal(kit.isRunning(z, at + 60_000), true);
  assert.equal(kit.isRunning(v, at + 60_000), true, "Voice's +00:00 timestamp parses");
  assert.equal(kit.isRunning(z, at + 4 * 60_000), false, "stale after three missed beats");
  assert.equal(kit.isRunning({ ...z, running: false }, at + 1000), false, "a clean exit's running:false is immediate");
  assert.equal(kit.isRunning({ ...z, updated_at: "garbage" }, at), false);
  assert.equal(kit.isRunning(null), false);
});

test("golden: the bytes the kit writes are the bytes shipped apps write", () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "kit-family-w-"));
  // Zevet's heartbeat (desktop/family.js heartbeat(): JSON.stringify of this body, this key order)
  const z = JSON.parse(bytes("zevet.json"));
  kit.writeHeartbeat(dir, "zevet", z);
  assert.equal(fs.readFileSync(path.join(dir, "zevet.json"), "utf8"), bytes("zevet.json"));
  // Masora's team.join request to Zevet (sibling-family.js writeZevetTeamJoinRequest)
  kit.writeRequest(dir, "zevet", { action: "team.join", team: "acme", key: "k-1", at: "2026-09-29T04:00:00.000Z" });
  assert.equal(fs.readFileSync(path.join(dir, "zevet.request.json"), "utf8"), bytes("zevet.request.json"));
  // Zevet's panel asking Voice to update (family.js #request)
  kit.writeRequest(dir, "voice", { action: "update", requested_by: "zevet", at: "2026-09-29T04:00:00.000Z" });
  assert.equal(fs.readFileSync(path.join(dir, "voice.request.json"), "utf8"), bytes("voice.request.json"));
  assert.deepEqual(fs.readdirSync(dir).filter((f) => f.endsWith(".tmp")), [], "no temp file is left behind");
});

test("takeRequest reads, deletes, and only then returns; a second take finds nothing", () => {
  const dir = copyGolden();
  assert.deepEqual(kit.takeRequest(dir, "voice"), { action: "update", requested_by: "zevet", at: "2026-09-29T04:00:00.000Z" });
  assert.equal(fs.existsSync(path.join(dir, "voice.request.json")), false);
  assert.equal(kit.takeRequest(dir, "voice"), null);
  assert.equal(kit.takeRequest(dir, "nobody"), null);
  fs.writeFileSync(path.join(dir, "zevet.request.json"), "not json");
  assert.equal(kit.takeRequest(dir, "zevet"), null);
});

test("readJson: objects only; masoraWeb only for the desktop runtime, without a trailing slash", () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "kit-family-j-"));
  const w = (f, s) => fs.writeFileSync(path.join(dir, f), s);
  w("a.json", "[1]");
  w("b.json", "5");
  w("c.json", "{oops");
  assert.equal(kit.readJson(path.join(dir, "a.json")), null);
  assert.equal(kit.readJson(path.join(dir, "b.json")), null);
  assert.equal(kit.readJson(path.join(dir, "c.json")), null);
  assert.equal(kit.readJson(path.join(dir, "missing.json")), null);
  assert.equal(kit.masoraWeb(dir), "");
  w("masora.json", '{"runtime":"something-else","web":"http://x"}');
  assert.equal(kit.masoraWeb(dir), "");
  w("masora.json", '{"runtime":"masora-desktop","web":"http://127.0.0.1:3210///"}');
  assert.equal(kit.masoraWeb(dir), "http://127.0.0.1:3210");
  w("masora.json", '{"runtime":"masora-desktop","web":3210}');
  assert.equal(kit.masoraWeb(dir), "");
});

test("readKey: trims, and a missing or blank key is null", () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "kit-family-k-"));
  assert.equal(kit.readKey(dir), null);
  fs.writeFileSync(path.join(dir, "family.key"), "  abc\r\n");
  assert.equal(kit.readKey(dir), "abc");
  fs.writeFileSync(path.join(dir, "family.key"), "\n");
  assert.equal(kit.readKey(dir), null);
});

test("ensureKey: creates 32 random bytes as hex, restricts the file BEFORE the secret lands, and is create-once", () => {
  const dir = path.join(fs.mkdtempSync(path.join(os.tmpdir(), "kit-family-e-")), "fam");
  const seen = [];
  const restrict = (file) => seen.push(fs.readFileSync(file, "utf8"));
  const key = kit.ensureKey(dir, { restrict });
  assert.match(key, /^[0-9a-f]{64}$/);
  assert.deepEqual(seen, [""], "the file was empty when it was restricted");
  assert.equal(fs.readFileSync(path.join(dir, "family.key"), "utf8"), key, "no newline: the bytes Masora's runtime writes");
  assert.equal(kit.ensureKey(dir, { restrict: () => assert.fail("must not restrict again") }), key);
  // a malformed existing key is replaced; a restrict failure is raised, not swallowed
  fs.writeFileSync(path.join(dir, "family.key"), "short");
  assert.match(kit.ensureKey(dir, { restrict }), /^[0-9a-f]{64}$/);
  fs.rmSync(path.join(dir, "family.key"));
  assert.throws(() => kit.ensureKey(dir, { restrict: () => { throw new Error("nope"); } }), /nope/);
});

test("the real restriction leaves a key only this user can read", () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "kit-family-r-"));
  const key = kit.ensureKey(dir);
  const file = path.join(dir, "family.key");
  assert.equal(fs.readFileSync(file, "utf8"), key);
  if (process.platform === "win32") {
    const { spawnSync } = require("node:child_process");
    const acl = spawnSync("icacls", [file], { encoding: "utf8", windowsHide: true }).stdout;
    assert.match(acl, new RegExp(os.userInfo().username, "i"));
    assert.doesNotMatch(acl, /Everyone|BUILTIN\\Users/i, "no broad grant survives");
  } else {
    assert.equal(fs.statSync(file).mode & 0o777, 0o600);
  }
});
