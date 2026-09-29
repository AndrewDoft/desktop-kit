"use strict";
const { test } = require("node:test");
const assert = require("node:assert/strict");
const { createServer } = require("node:http");
const { createHash, randomBytes, generateKeyPairSync } = require("node:crypto");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const { UpdaterCore, compareVersions, safeArtifactName, artifactUrl, readManifest, signDocument } = require("..");

const DOMAIN = "kit-test-v1\n";
const KEY = generateKeyPairSync("ed25519");
const PEM = KEY.privateKey.export({ format: "pem", type: "pkcs8" });
const KEYS = { "k1": KEY.publicKey.export({ format: "der", type: "spki" }).subarray(-32).toString("base64") };
const sha = (b) => createHash("sha256").update(b).digest("hex");
const ARTIFACT = (v, key) => (key === "win32-x64" ? `app-${v}-setup.exe` : null);

function feed(version, bytes, { file = `app-${version}-setup.exe`, field = "payload", key = PEM, doc } = {}) {
  const d = doc || { schema: 1, version, notes: "n", platforms: { "win32-x64": { file, bytes: bytes.length, sha256: sha(bytes) } } };
  return { version, [field]: d, signature: signDocument(DOMAIN, d, key, "k1") };
}

async function serve(files, t) {
  const hits = [];
  const server = createServer((req, res) => {
    const name = req.url.split("?")[0].slice(1);
    hits.push(name);
    if (!(name in files)) return res.writeHead(404).end();
    res.writeHead(200).end(typeof files[name] === "object" && !Buffer.isBuffer(files[name]) ? JSON.stringify(files[name]) : files[name]);
  });
  await new Promise((r) => server.listen(0, "127.0.0.1", r));
  t.after(() => new Promise((r) => server.close(r)));
  return { base: `http://127.0.0.1:${server.address().port}/`, hits };
}

function updater(h, extra = {}) {
  return new UpdaterCore({
    currentVersion: "1.0.0",
    feedUrl: `${h.base}latest.json`,
    domain: DOMAIN,
    trustedKeys: KEYS,
    feedField: "payload",
    platform: "win32",
    platformKey: "win32-x64",
    dir: fs.mkdtempSync(path.join(os.tmpdir(), "kit-upd-")),
    artifactName: ARTIFACT,
    ...extra,
  });
}

test("check -> download -> verify -> ready; install and install-on-quit are the injected steps", async (t) => {
  const bytes = randomBytes(4096);
  const h = await serve({ "latest.json": feed("2.0.0", bytes), "app-2.0.0-setup.exe": bytes }, t);
  const calls = [];
  const seen = [];
  const u = updater(h, { onStatus: (s) => seen.push(s.phase), steps: { restart: () => { calls.push("restart"); return { ok: true, restarting: true }; }, onQuit: () => { calls.push("quit"); return { ok: true }; } } });
  const s = await u.check();
  assert.equal(s.phase, "ready");
  assert.equal(s.version, "2.0.0");
  assert.equal(s.canInstall, true);
  assert.ok(seen.includes("downloading") && seen.at(-1) === "ready");
  assert.deepEqual(fs.readFileSync(s.file), bytes);
  assert.deepEqual(await u.install(), { ok: true, restarting: true });
  assert.deepEqual(u.installOnQuit(), { ok: true });
  // the marker makes the quit install a one-shot per version
  assert.match(u.installOnQuit().error, /already attempted/);
  assert.deepEqual(calls, ["restart", "quit"]);
  // a second check while ready does not re-download
  const before = h.hits.filter((n) => n.endsWith(".exe")).length;
  await u.check();
  assert.equal(h.hits.filter((n) => n.endsWith(".exe")).length, before);
});

test("the Masora {signed} layout works when the app pins it; the wrong layout is refused", async (t) => {
  const bytes = randomBytes(64);
  const h = await serve({ "latest.json": feed("2.0.0", bytes, { field: "signed" }), "app-2.0.0-setup.exe": bytes }, t);
  assert.equal((await updater(h, { feedField: "signed" }).check()).phase, "ready");
  assert.match((await updater(h, { feedField: "payload" }).check()).error, /not validly signed/);
});

test("an unsigned, foreign-key or tampered feed is rejected and nothing is downloaded", async (t) => {
  const bytes = randomBytes(64);
  const other = generateKeyPairSync("ed25519").privateKey.export({ format: "pem", type: "pkcs8" });
  const tampered = feed("2.0.0", bytes);
  tampered.payload.platforms["win32-x64"].sha256 = "0".repeat(64);
  const { signature: _s, ...unsigned } = feed("2.0.0", bytes);
  for (const [name, body, re] of [["unsigned", unsigned, /not validly signed/], ["foreign", feed("2.0.0", bytes, { key: other }), /does not match/], ["tampered", tampered, /does not match/]]) {
    const h = await serve({ "latest.json": body, "app-2.0.0-setup.exe": bytes }, t);
    const s = await updater(h).check();
    assert.equal(s.phase, "error", name);
    assert.match(s.error, re, name);
    assert.deepEqual(h.hits, ["latest.json"], name);
  }
});

test("bytes that do not match the signed sha256 are discarded, never left as an installer", async (t) => {
  const good = randomBytes(256);
  const evil = Buffer.from(good);
  evil[0] ^= 0xff;
  const h = await serve({ "latest.json": feed("2.0.0", good), "app-2.0.0-setup.exe": evil }, t);
  const u = updater(h);
  const s = await u.check();
  assert.equal(s.phase, "error");
  assert.match(s.error, /checksum/);
  assert.deepEqual(fs.readdirSync(u.dir), []);
});

test("a download longer than the signed size is refused; a 404 feed is 'current', not an error", async (t) => {
  const good = randomBytes(64);
  const h = await serve({ "latest.json": feed("2.0.0", good), "app-2.0.0-setup.exe": Buffer.concat([good, good]) }, t);
  assert.match((await updater(h).check()).error, /longer than the manifest|manifest says/);
  const empty = await serve({}, t);
  const s = await updater(empty).check();
  assert.equal(s.phase, "current");
  assert.equal(s.error, null);
});

test("nothing newer -> current, and old installers are swept", async (t) => {
  const bytes = randomBytes(32);
  const h = await serve({ "latest.json": feed("1.0.0", bytes) }, t);
  const u = updater(h);
  fs.mkdirSync(u.dir, { recursive: true });
  fs.writeFileSync(path.join(u.dir, "app-0.9.0-setup.exe"), "old");
  fs.writeFileSync(path.join(u.dir, "install-on-quit.json"), "{}");
  assert.equal((await u.check()).phase, "current");
  assert.deepEqual(fs.readdirSync(u.dir), ["install-on-quit.json"]);
});

test("a file that changes after 'ready' is refused at install time", async (t) => {
  const bytes = randomBytes(128);
  const h = await serve({ "latest.json": feed("2.0.0", bytes), "app-2.0.0-setup.exe": bytes }, t);
  const u = updater(h, { steps: { restart: () => assert.fail("must not run"), onQuit: () => assert.fail("must not run") } });
  const s = await u.check();
  fs.writeFileSync(s.file, randomBytes(128));
  const r = await u.install();
  assert.equal(r.ok, false);
  assert.match(r.error, /changed/);
  assert.equal(u.state.phase, "error");

  // and one that vanished is reported as gone, and the state falls back to idle
  const s2 = await updater(h, { steps: { restart: () => assert.fail("must not run") } });
  await s2.check();
  fs.rmSync(s2.state.file);
  assert.match((await s2.install()).error, /gone/);
  assert.equal(s2.state.phase, "idle");
});

test("publisherProblem can veto the installer, which is then deleted", async (t) => {
  const bytes = randomBytes(64);
  const h = await serve({ "latest.json": feed("2.0.0", bytes), "app-2.0.0-setup.exe": bytes }, t);
  const u = updater(h, { steps: { publisherProblem: async () => "not signed by us" } });
  const s = await u.check();
  assert.equal(s.phase, "error");
  assert.equal(s.error, "not signed by us");
  assert.deepEqual(fs.readdirSync(u.dir), []);
});

test("install with nothing downloaded, or with no platform step, is an honest error", async (t) => {
  const h = await serve({}, t);
  assert.match((await updater(h).install()).error, /nothing downloaded/);
  const bytes = randomBytes(16);
  const h2 = await serve({ "latest.json": feed("2.0.0", bytes), "app-2.0.0-setup.exe": bytes }, t);
  const u = updater(h2);
  await u.check();
  assert.match((await u.install()).error, /not published/);
  assert.match(u.installOnQuit().error, /cannot install silently/);
});

test("the manifest picks a FILE beside the feed, never a host or another path", () => {
  const f = "http://127.0.0.1:1/dl/latest.json";
  assert.equal(artifactUrl(f, "a-1.exe").href, "http://127.0.0.1:1/dl/a-1.exe");
  for (const bad of ["../a.exe", "https://evil.example/a.exe", "a/b.exe", "a.sh", "", "a..b.exe"]) assert.equal(artifactUrl(f, bad), null, bad);
  assert.ok(safeArtifactName("x.dmg") && safeArtifactName("x.exe") && !safeArtifactName("x.msi"));
  assert.ok(safeArtifactName("x.msi", /\.msi$/));
});

test("readManifest: versions compare numerically; bad entries reject the whole manifest", () => {
  assert.equal(compareVersions("0.10.0", "0.9.0"), 1);
  assert.equal(compareVersions("1.0", "1.0.0"), 0);
  const ok = { version: "2.0.0", platforms: { "win32-x64": { file: "app-2.0.0-setup.exe", bytes: 5, sha256: "a".repeat(64) } } };
  assert.equal(readManifest(ok, "win32-x64", { artifactName: ARTIFACT }).entry.bytes, 5);
  assert.match(readManifest(ok, "darwin-arm64", { artifactName: ARTIFACT }).error, /no build for/);
  assert.match(readManifest({ ...ok, version: "2.0.1" }, "win32-x64", { artifactName: ARTIFACT }).error, /is not the/);
  assert.match(readManifest({ ...ok, platforms: { "win32-x64": { ...ok.platforms["win32-x64"], sha256: "zz" } } }, "win32-x64").error, /sha256/);
  assert.match(readManifest({ ...ok, platforms: { "win32-x64": { ...ok.platforms["win32-x64"], bytes: 5e9 } } }, "win32-x64").error, /size/);
  assert.match(readManifest({ ...ok, version: "x" }, "win32-x64").error, /version/);
});

test("canOnQuit=false refuses before the one-shot marker is written", async (t) => {
  const bytes = randomBytes(16);
  const h = await serve({ "latest.json": feed("2.0.0", bytes), "app-2.0.0-setup.exe": bytes }, t);
  const u = updater(h, { steps: { onQuit: () => assert.fail("must not run"), canOnQuit: () => false } });
  await u.check();
  assert.match(u.installOnQuit().error, /cannot install silently/);
  assert.equal(fs.existsSync(path.join(u.dir, "install-on-quit.json")), false);
});

test("constructor refuses missing trust config", () => {
  assert.throws(() => new UpdaterCore({ feedUrl: "http://x/", trustedKeys: {} }), /domain/);
  assert.throws(() => new UpdaterCore({ feedUrl: "http://x/", domain: "d" }), /trustedKeys/);
  assert.throws(() => new UpdaterCore({ domain: "d", trustedKeys: {} }), /feedUrl/);
});
