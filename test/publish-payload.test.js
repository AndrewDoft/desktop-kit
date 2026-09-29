"use strict";
const { test } = require("node:test");
const assert = require("node:assert/strict");
const { spawnSync } = require("node:child_process");
const { generateKeyPairSync, createHash } = require("node:crypto");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const { verifyFeed, PULSE_DOMAIN } = require("..");

const BIN = path.join(__dirname, "..", "bin", "publish-payload.mjs");
const KEY = generateKeyPairSync("ed25519");
const PEM = KEY.privateKey.export({ format: "pem", type: "pkcs8" });
const KEYS = { k1: KEY.publicKey.export({ format: "der", type: "spki" }).subarray(-32).toString("base64") };
const ENV = { ...process.env, TEST_SIGNING_KEY: PEM.trim().replaceAll("\n", "|") };
const A = ["--app", "app1", "--platform", "win-x64"];
const KEYARGS = ["--key-env", "TEST_SIGNING_KEY", "--key-id", "k1"];

const tmp = () => fs.mkdtempSync(path.join(os.tmpdir(), "kit-pub-"));
const run = (args, env = ENV) => spawnSync(process.execPath, [BIN, ...args], { env, encoding: "utf8" });
const ok = (args) => { const r = run(args); assert.equal(r.status, 0, r.stderr); return r; };
const bad = (args, re) => { const r = run(args); assert.notEqual(r.status, 0); assert.match(r.stderr, re); };
const pulse = (out, channel) => {
  const body = JSON.parse(fs.readFileSync(path.join(out, "p", "app1", channel, "win-x64", "pulse.json"), "utf8"));
  return verifyFeed(body, PULSE_DOMAIN, KEYS, "signed"); // throws unless signed by k1
};
function publish(out, channel, build, seq, extra = []) {
  const tree = tmp();
  fs.writeFileSync(path.join(tree, "f.txt"), `content of ${build}`);
  ok([...A, "--channel", channel, "--build", build, "--seq", String(seq), "--schema-head", "7", "--shell-min", "2",
    "--tree", tree, "--out", out, ...KEYARGS, ...extra]);
}
/** sha256 of every file under out/p/b and out/p/m, so "bytes never touched" is checkable. */
function bytes(out) {
  const acc = {};
  for (const sub of ["b", "m"]) {
    const walk = (d) => fs.readdirSync(d, { withFileTypes: true }).forEach((e) => {
      const f = path.join(d, e.name);
      e.isDirectory() ? walk(f) : (acc[path.relative(out, f)] = createHash("sha256").update(fs.readFileSync(f)).digest("hex"));
    });
    walk(path.join(out, "p", sub));
  }
  return acc;
}

test("publish signs with a raw PEM, `|`-encoded or with real newlines; the JSON form is gone", () => {
  const out = tmp();
  publish(out, "canary", "1.0.0", 1);
  assert.equal(pulse(out, "canary").build, "1.0.0");
  const tree = tmp();
  fs.writeFileSync(path.join(tree, "f.txt"), "x");
  const args = [...A, "--channel", "canary", "--build", "1.0.1", "--seq", "2", "--schema-head", "7", "--shell-min", "2", "--tree", tree, "--out", out, ...KEYARGS];
  assert.equal(run(args, { ...process.env, TEST_SIGNING_KEY: PEM }).status, 0);
  assert.equal(pulse(out, "canary").build, "1.0.1");
  bad(args.map((a) => (a === "2" ? "1" : a)), /refusing to publish seq 1/);
  bad(args.map((a) => (a === "2" ? "1" : a)), /refusing to publish seq 1/);
  const json = JSON.stringify({ key_id: "k1", private_key: PEM });
  const r = run(args.map((a) => (a === "2" ? "3" : a)), { ...process.env, TEST_SIGNING_KEY: json });
  assert.notEqual(r.status, 0);
  assert.match(r.stderr, /not a PEM private key/);
  assert.doesNotMatch(r.stderr + r.stdout, /BEGIN|MC4C/, "the key never reaches the output");
});

test("promote copies canary's build/manifest/schema_head/shell_min to stable and touches no bytes", () => {
  const out = tmp();
  publish(out, "stable", "1.0.0", 116);
  publish(out, "canary", "1.1.0", 117);
  const before = bytes(out);
  ok(["promote", ...A, "--from", "canary", "--to", "stable", "--out", out, ...KEYARGS]);
  const c = pulse(out, "canary");
  const s = pulse(out, "stable");
  assert.deepEqual([s.channel, s.build, s.manifest, s.schema_head, s.shell_min, s.paused, s.rollout], ["stable", "1.1.0", c.manifest, 7, 2, false, 100]);
  assert.equal(s.seq, 117, "normal case: stable takes the canary seq");
  assert.deepEqual(bytes(out), before);
});

test("promote keeps seq strictly increasing when stable is already past canary; refuses no-ops and missing manifests", () => {
  const out = tmp();
  publish(out, "stable", "1.0.0", 120);
  publish(out, "canary", "1.1.0", 117);
  const P = ["promote", ...A, "--from", "canary", "--to", "stable", "--out", out, ...KEYARGS];
  ok(P);
  assert.equal(pulse(out, "stable").seq, 121);
  bad(P, /already carries 1\.1\.0/);
  bad(["promote", ...A, "--from", "canary", "--to", "canary", "--out", out, ...KEYARGS], /must differ/);
  const gone = tmp();
  publish(gone, "canary", "2.0.0", 5);
  fs.rmSync(path.join(gone, "p", "m"), { recursive: true });
  bad(["promote", ...A, "--from", "canary", "--to", "stable", "--out", gone, ...KEYARGS], /manifest .* is not in/);
});

test("pause and resume re-sign the same seq, flip only `paused`, and refuse a no-op", () => {
  const out = tmp();
  publish(out, "stable", "1.0.0", 5);
  const before = pulse(out, "stable");
  const args = (s) => [s, ...A, "--channel", "stable", "--out", out, ...KEYARGS];
  bad(args("resume"), /already running/);
  ok(args("pause"));
  const p = pulse(out, "stable");
  assert.deepEqual([p.paused, p.seq, p.build, p.manifest], [true, 5, "1.0.0", before.manifest]);
  bad(args("pause"), /already paused/);
  ok(args("resume"));
  assert.deepEqual([pulse(out, "stable").paused, pulse(out, "stable").seq], [false, 5]);
});

test("rollback points the pulse at an older build's existing manifest, seq+1, `rollback` names the build left", () => {
  const out = tmp();
  publish(out, "stable", "1.0.0", 5);
  const old = pulse(out, "stable").manifest;
  publish(out, "stable", "1.1.0", 6);
  const before = bytes(out);
  const R = (to, extra = []) => ["rollback", ...A, "--channel", "stable", "--to", to, "--out", out, ...KEYARGS, ...extra];
  ok(R("1.0.0"));
  const p = pulse(out, "stable");
  assert.deepEqual([p.build, p.seq, p.rollback, p.manifest], ["1.0.0", 7, "1.1.0", old]);
  assert.deepEqual(bytes(out), before);
  bad(R("1.0.0"), /already on 1\.0\.0/);
  bad(R("9.9.9"), /0 manifests for build 9\.9\.9/);
  bad(R("1.1.0", ["--manifest", "0".repeat(64)]), /manifest 0+ is not in/);
  ok(R("1.1.0", ["--schema-head", "9", "--shell-min", "3"]));
  const q = pulse(out, "stable");
  assert.deepEqual([q.build, q.seq, q.rollback, q.schema_head, q.shell_min], ["1.1.0", 8, "1.0.0", 9, 3]);
  fs.writeFileSync(path.join(out, "p", "m", `${"a".repeat(64)}.json`), JSON.stringify({ build: "1.0.0", platform: "win-x64", files: [] }));
  bad(R("1.0.0"), /2 manifests for build 1.0.0.*--manifest/);
  ok(R("1.0.0", ["--manifest", old]));
});

test("publish refuses a build id that would not be a safe directory name (finding 6)", () => {
  const out = tmp();
  const tree = tmp();
  fs.writeFileSync(path.join(tree, "f.txt"), "x");
  bad([...A, "--channel", "canary", "--build", "..", "--seq", "1", "--schema-head", "7", "--shell-min", "2", "--tree", tree, "--out", out, ...KEYARGS], /invalid build/);
});

test("rollback refuses a --to build id that would not be a safe directory name (finding 6)", () => {
  const out = tmp();
  publish(out, "stable", "1.0.0", 1);
  bad(["rollback", ...A, "--channel", "stable", "--to", "../escape", "--out", out, ...KEYARGS], /invalid build/);
});

test("publish dereferences a symlink to an in-tree regular file and ships it as an ordinary manifest entry", () => {
  const out = tmp();
  const tree = tmp();
  fs.writeFileSync(path.join(tree, "real.txt"), "hello");
  try {
    fs.symlinkSync(path.join(tree, "real.txt"), path.join(tree, "link.txt"));
  } catch (err) {
    if (err.code === "EPERM") return; // no symlink privilege on this runner; nothing to assert
    throw err;
  }
  ok([...A, "--channel", "canary", "--build", "1.0.0", "--seq", "1", "--schema-head", "7", "--shell-min", "2", "--tree", tree, "--out", out, ...KEYARGS]);
  const manifestHash = pulse(out, "canary").manifest;
  const manifest = JSON.parse(fs.readFileSync(path.join(out, "p", "m", `${manifestHash}.json`), "utf8"));
  const entry = manifest.files.find((f) => f.p === "link.txt");
  assert.ok(entry, "the symlink was shipped as an ordinary file entry");
  assert.equal(entry.h, createHash("sha256").update("hello").digest("hex"));
});

test("publish refuses a symlink that resolves outside the tree, to a directory, or dangles", () => {
  const tree = tmp();
  fs.writeFileSync(path.join(tree, "real.txt"), "x");
  const publishArgs = () => [...A, "--channel", "canary", "--build", "1.0.0", "--seq", "1", "--schema-head", "7", "--shell-min", "2", "--tree", tree, "--out", tmp(), ...KEYARGS];

  const outside = tmp();
  fs.writeFileSync(path.join(outside, "secret.txt"), "s");
  try {
    fs.symlinkSync(path.join(outside, "secret.txt"), path.join(tree, "escape.txt"));
  } catch (err) {
    if (err.code === "EPERM") return; // no symlink privilege on this runner; nothing to assert
    throw err;
  }
  bad(publishArgs(), /resolves outside the tree/);
  fs.rmSync(path.join(tree, "escape.txt"));

  fs.mkdirSync(path.join(tree, "dir"));
  fs.symlinkSync(path.join(tree, "dir"), path.join(tree, "dirlink"));
  bad(publishArgs(), /does not resolve to a regular file/);
  fs.rmSync(path.join(tree, "dirlink"));

  fs.symlinkSync(path.join(tree, "nope.txt"), path.join(tree, "link2.txt"));
  bad(publishArgs(), /symlink target does not exist/);
});

test("publish refuses a --have file containing something that is not a sha256 hash", () => {
  const out = tmp();
  const tree = tmp();
  fs.writeFileSync(path.join(tree, "f.txt"), "x");
  const haveFile = path.join(tmp(), "have.txt");
  fs.writeFileSync(haveFile, "not-a-hash\n");
  bad([...A, "--channel", "canary", "--build", "1.0.0", "--seq", "1", "--schema-head", "7", "--shell-min", "2", "--tree", tree, "--out", out, "--have", haveFile, ...KEYARGS], /--have contains an invalid hash/);
});
