"use strict";
const { test } = require("node:test");
const assert = require("node:assert/strict");
const { createServer } = require("node:http");
const { createHash, randomBytes, generateKeyPairSync } = require("node:crypto");
const { brotliCompressSync } = require("node:zlib");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const { createPayloadClient, hashTree, signDocument, PULSE_DOMAIN } = require("..");

const sha = (b) => createHash("sha256").update(b).digest("hex");
const KEY = generateKeyPairSync("ed25519");
const PEM = KEY.privateKey.export({ format: "pem", type: "pkcs8" });
const KEYS = { k1: KEY.publicKey.export({ format: "der", type: "spki" }).subarray(-32).toString("base64") };

const tmpRoot = (name) => fs.mkdtempSync(path.join(os.tmpdir(), `kit-pay-${name}-`));

/** A tiny static server over a live, mutable `files` object (relative path -> Buffer|object).
 *  Supports Range (for resume) and a one-shot `killOnce(path, byteLimit)` that writes only the
 *  first `byteLimit` bytes then destroys the connection, simulating a dropped download. */
async function serve(files, t) {
  const hits = [];
  const kill = new Map();
  const server = createServer((req, res) => {
    const name = req.url.split("?")[0].slice(1);
    hits.push(name);
    if (!(name in files)) { res.writeHead(404).end(); return; }
    const raw = files[name];
    const buf = Buffer.isBuffer(raw) ? raw : Buffer.from(JSON.stringify(raw));
    const range = req.headers.range;
    if (kill.has(name) && !range) {
      const limit = kill.get(name);
      kill.delete(name);
      res.writeHead(200, { "content-length": String(buf.length) });
      res.write(buf.subarray(0, limit), () => res.destroy());
      return;
    }
    if (range) {
      const m = /^bytes=(\d+)-$/.exec(range);
      const start = m ? parseInt(m[1], 10) : 0;
      res.writeHead(206, { "content-range": `bytes ${start}-${buf.length - 1}/${buf.length}`, "content-length": String(buf.length - start) });
      res.end(buf.subarray(start));
      return;
    }
    res.writeHead(200, { "content-length": String(buf.length) });
    res.end(buf);
  });
  await new Promise((r) => server.listen(0, "127.0.0.1", r));
  t.after(() => new Promise((r) => server.close(r)));
  return { base: `http://127.0.0.1:${server.address().port}/`, files, hits, killOnce: (name, limit) => kill.set(name, limit) };
}

/** Builds a signed pulse + manifest + blobs for one build, keyed at the exact wire paths
 *  (`p/<app>/<channel>/<platform>/pulse.json`, `p/m/<sha>.json`, `p/b/<sha[0:2]>/<sha>`). */
function fixture({ app = "app1", channel = "stable", platform = "win-x64", build, seq, files, rollout = 100, paused = false, shellMin = 0, schemaHead = 0, rollback, key = PEM, keyId = "k1" }) {
  const manifestFiles = files.map((f) => ({ p: f.p, h: sha(f.raw), s: f.raw.length, x: !!f.x }));
  const manifest = { build, platform, files: manifestFiles, entry: {} };
  const manifestBytes = Buffer.from(JSON.stringify(manifest));
  const manifestHash = sha(manifestBytes);
  const doc = {
    app, channel, platform, build, seq, manifest: manifestHash,
    shell_min: shellMin, schema_head: schemaHead, rollout, paused,
    issued: new Date().toISOString(), ...(rollback ? { rollback } : {}),
  };
  const registry = {
    [`p/${app}/${channel}/${platform}/pulse.json`]: { signed: doc, signature: signDocument(PULSE_DOMAIN, doc, key, keyId) },
    [`p/m/${manifestHash}.json`]: manifestBytes,
  };
  for (const f of files) registry[`p/b/${sha(f.raw).slice(0, 2)}/${sha(f.raw)}`] = brotliCompressSync(f.raw);
  return { app, channel, platform, doc, manifest, registry };
}

function client(h, fx, extra = {}) {
  return createPayloadClient({
    app: fx.app, channel: fx.channel, platform: fx.platform,
    root: tmpRoot("root"),
    pulseUrl: `${h.base}p/${fx.app}/${fx.channel}/${fx.platform}/pulse.json`,
    keys: KEYS,
    installId: "install-1",
    ...extra,
  });
}

test("happy path: check -> staged -> activate -> confirm; resolve() sees it", async (t) => {
  const files = [{ p: "app/main.js", raw: randomBytes(512) }, { p: "app/bin/tool", raw: randomBytes(128), x: true }];
  const fx = fixture({ build: "1.0.0", seq: 1, files });
  const h = await serve(fx.registry, t);
  const c = client(h, fx);

  const r = await c.check();
  assert.equal(r.status, "staged");
  assert.equal(r.build, "1.0.0");
  const staged = c.staged();
  assert.equal(staged.build, "1.0.0");
  assert.deepEqual(fs.readFileSync(path.join(staged.dir, "app", "main.js")), files[0].raw);

  const act = c.activate();
  assert.equal(act.build, "1.0.0");
  assert.equal(act.previous, null);
  c.confirm();

  const res = c.resolve();
  assert.equal(res.source, "current");
  assert.equal(res.build, "1.0.0");
  assert.equal(res.trial, false);
  assert.equal(c.staged(), null, "activation clears the staged marker");
});

test("seed mapping: files matching the seed's hash come from the seed, not the network", async (t) => {
  const unchanged = randomBytes(1024);
  const changed = randomBytes(64);
  const seedDir = tmpRoot("seed");
  fs.mkdirSync(path.join(seedDir, "sub"), { recursive: true });
  fs.writeFileSync(path.join(seedDir, "unchanged.bin"), unchanged);
  fs.writeFileSync(path.join(seedDir, "sub", "old.bin"), randomBytes(64));

  const fx = fixture({ build: "2.0.0", seq: 2, files: [{ p: "unchanged.bin", raw: unchanged }, { p: "sub/old.bin", raw: changed }] });
  const h = await serve(fx.registry, t);
  const c = client(h, fx, { seedDir, seedBuild: "seed-1", seedSeq: 1 });

  const r = await c.check();
  assert.equal(r.status, "staged");
  const blobHits = h.hits.filter((n) => n.startsWith("p/b/"));
  assert.deepEqual(blobHits, [`p/b/${sha(changed).slice(0, 2)}/${sha(changed)}`], "only the changed file's blob is fetched over the network");
  assert.deepEqual(fs.readFileSync(path.join(c.staged().dir, "unchanged.bin")), unchanged);
});

test("a corrupted blob that fails to decompress is rejected; nothing is staged", async (t) => {
  const raw = randomBytes(256);
  const fx = fixture({ build: "3.0.0", seq: 1, files: [{ p: "f.bin", raw }] });
  const blobKey = Object.keys(fx.registry).find((k) => k.startsWith("p/b/"));
  const bytes = Buffer.from(fx.registry[blobKey]);
  bytes[bytes.length - 1] ^= 0xff;
  fx.registry[blobKey] = bytes;
  const h = await serve(fx.registry, t);
  const c = client(h, fx);
  await assert.rejects(c.check(), /decompress/);
  assert.equal(c.staged(), null);
});

test("a blob that decompresses cleanly but to the wrong bytes is rejected (hash mismatch)", async (t) => {
  const raw = randomBytes(256);
  const wrong = randomBytes(256);
  const fx = fixture({ build: "3.1.0", seq: 1, files: [{ p: "f.bin", raw }] });
  const blobKey = Object.keys(fx.registry).find((k) => k.startsWith("p/b/"));
  fx.registry[blobKey] = brotliCompressSync(wrong); // valid brotli, wrong content
  const h = await serve(fx.registry, t);
  const c = client(h, fx);
  await assert.rejects(c.check(), /tampered/);
  assert.equal(c.staged(), null);
});

test("a manifest whose bytes do not match the pulse's hash is rejected", async (t) => {
  const fx = fixture({ build: "4.0.0", seq: 1, files: [{ p: "f.bin", raw: randomBytes(32) }] });
  const manifestKey = Object.keys(fx.registry).find((k) => k.startsWith("p/m/"));
  // still valid JSON with the right build/platform/hashes — only the hash-of-bytes check catches this
  const manifest = JSON.parse(fx.registry[manifestKey].toString("utf8"));
  manifest.files[0].s += 1;
  fx.registry[manifestKey] = Buffer.from(JSON.stringify(manifest));
  const h = await serve(fx.registry, t);
  const c = client(h, fx);
  await assert.rejects(c.check(), /tampered/);
});

test("a pulse signed by an untrusted key is rejected", async (t) => {
  const other = generateKeyPairSync("ed25519").privateKey.export({ format: "pem", type: "pkcs8" });
  const fx = fixture({ build: "5.0.0", seq: 1, files: [{ p: "f.bin", raw: randomBytes(16) }], key: other });
  const h = await serve(fx.registry, t);
  const c = client(h, fx);
  await assert.rejects(c.check(), /does not match/);
});

test("an unsigned pulse is rejected", async (t) => {
  const fx = fixture({ build: "6.0.0", seq: 1, files: [{ p: "f.bin", raw: randomBytes(16) }] });
  const pulseKey = Object.keys(fx.registry).find((k) => k.endsWith("pulse.json"));
  fx.registry[pulseKey] = { signed: fx.registry[pulseKey].signed };
  const h = await serve(fx.registry, t);
  const c = client(h, fx);
  await assert.rejects(c.check(), /not signed/);
});

test("seq only moves forward, except a signed rollback naming the exact current build", async (t) => {
  const h = await serve({}, t);
  const fx1 = fixture({ build: "1.0.0", seq: 5, files: [{ p: "f.bin", raw: randomBytes(16) }] });
  Object.assign(h.files, fx1.registry);
  const c = client(h, fx1);
  assert.equal((await c.check()).status, "staged");
  c.activate();
  c.confirm();

  const fx2 = fixture({ build: "0.9.0", seq: 3, files: [{ p: "g.bin", raw: randomBytes(16) }] });
  Object.assign(h.files, fx2.registry);
  assert.equal((await c.check()).status, "none", "a lower seq without rollback is ignored");
  assert.equal(c.resolve().build, "1.0.0");

  const fx3 = fixture({ build: "0.9.0", seq: 3, files: [{ p: "g.bin", raw: randomBytes(16) }], rollback: "1.0.0" });
  Object.assign(h.files, fx3.registry);
  assert.equal((await c.check()).status, "staged", "a signed rollback naming the current build is honoured");
  assert.equal(c.staged().build, "0.9.0");
});

test("paused, not-in-rollout, needs-shell and schema_head all refuse before download", async (t) => {
  const raw = randomBytes(16);
  const mk = (over) => fixture({ build: "9.0.0", seq: 1, files: [{ p: "f.bin", raw }], ...over });

  {
    const fx = mk({ paused: true });
    const h = await serve(fx.registry, t);
    assert.equal((await client(h, fx).check()).status, "paused");
    assert.deepEqual(h.hits.filter((n) => n.startsWith("p/b/") || n.startsWith("p/m/")), []);
  }
  {
    const fx = mk({ rollout: 0 });
    const h = await serve(fx.registry, t);
    assert.equal((await client(h, fx).check()).status, "not-in-rollout");
  }
  {
    const fx = mk({ shellMin: 5 });
    const h = await serve(fx.registry, t);
    assert.equal((await client(h, fx, { shellVersion: 4 }).check()).status, "needs-shell");
  }
  {
    const fx = mk({ schemaHead: 10 });
    const h = await serve(fx.registry, t);
    assert.equal((await client(h, fx, { schemaHead: async () => 11 }).check()).status, "refused");
  }
});

test("a download killed mid-blob resumes with Range and completes correctly", async (t) => {
  const raw = randomBytes(200 * 1024);
  const fx = fixture({ build: "10.0.0", seq: 1, files: [{ p: "big.bin", raw }] });
  const h = await serve(fx.registry, t);
  const blobKey = Object.keys(fx.registry).find((k) => k.startsWith("p/b/"));
  h.killOnce(blobKey, Math.floor(fx.registry[blobKey].length / 2));
  const c = client(h, fx);

  await assert.rejects(c.check(), /./);
  assert.equal(c.staged(), null);
  const r = await c.check();
  assert.equal(r.status, "staged");
  assert.deepEqual(fs.readFileSync(path.join(c.staged().dir, "big.bin")), raw);
});

test("3 boot failures revert to previous and bad-list the build; a bad build is never re-staged", async (t) => {
  const h = await serve({}, t);
  const fxA = fixture({ build: "1.0.0", seq: 1, files: [{ p: "f.bin", raw: randomBytes(16) }] });
  Object.assign(h.files, fxA.registry);
  const c = client(h, fxA);
  await c.check();
  c.activate();
  c.confirm();

  const fxB = fixture({ build: "2.0.0", seq: 2, files: [{ p: "g.bin", raw: randomBytes(16) }] });
  Object.assign(h.files, fxB.registry);
  await c.check();
  c.activate();
  assert.equal(c.resolve().build, "2.0.0");

  assert.equal(c.bootFailed("crash 1").reverted, false);
  assert.equal(c.bootFailed("crash 2").reverted, false);
  const third = c.bootFailed("crash 3");
  assert.equal(third.reverted, true);
  assert.equal(c.resolve().build, "1.0.0");

  const bad = JSON.parse(fs.readFileSync(path.join(c.root, "bad.json"), "utf8"));
  assert.ok(bad.builds.includes("2.0.0"));

  Object.assign(h.files, fxB.registry);
  assert.equal((await c.check()).status, "none", "the bad build is never re-staged");
});

test("revert() without a previous build is an honest error", async (t) => {
  const fx = fixture({ build: "1.0.0", seq: 1, files: [{ p: "f.bin", raw: randomBytes(8) }] });
  const h = await serve(fx.registry, t);
  const c = client(h, fx);
  await c.check();
  c.activate();
  assert.throws(() => c.revert("no reason"), /no previous/);
});

test("verifyEntry re-hashes against the recorded manifest; throws on mismatch or unknown path", async (t) => {
  const raw = randomBytes(32);
  const fx = fixture({ build: "1.0.0", seq: 1, files: [{ p: "entry.js", raw }] });
  const h = await serve(fx.registry, t);
  const c = client(h, fx);
  await c.check();
  c.activate();
  assert.doesNotThrow(() => c.verifyEntry(["entry.js"]));
  // the store's blobs (and hardlinks to them) are read-only; simulate a tamper attempt the way
  // an attacker with directory-write-but-not-file-write access would have to: chmod, then replace.
  const dir = c.resolve().dir;
  const entryPath = path.join(dir, "entry.js");
  fs.chmodSync(entryPath, 0o666);
  fs.writeFileSync(entryPath, randomBytes(32));
  assert.throws(() => c.verifyEntry(["entry.js"]), /does not match/);
  assert.throws(() => c.verifyEntry(["missing.js"]), /is not part of/);
});

test("gc keeps the 3 most recent version trees and sweeps unreferenced blobs", async (t) => {
  const h = await serve({}, t);
  const APP = { app: "gcapp", channel: "stable", platform: "win-x64" };
  const c = client(h, APP);
  const hashes = [];
  for (let i = 1; i <= 4; i++) {
    const raw = randomBytes(16);
    hashes.push(sha(raw));
    const fx = fixture({ ...APP, build: `${i}.0.0`, seq: i, files: [{ p: `f${i}.bin`, raw }] });
    Object.assign(h.files, fx.registry);
    await c.check();
    c.activate();
    c.confirm();
  }
  const versions = fs.readdirSync(path.join(c.root, "versions"));
  assert.equal(versions.length, 3, "only 3 version trees remain");
  assert.ok(!versions.includes("1.0.0"));
  assert.ok(!fs.existsSync(path.join(c.root, "store", hashes[0].slice(0, 2), hashes[0])), "build 1's blob is swept");
  assert.ok(fs.existsSync(path.join(c.root, "store", hashes[3].slice(0, 2), hashes[3])), "build 4's blob remains");
});

test("resolve() falls back to the seed, then throws when there is neither a build nor a seed", () => {
  const seedDir = tmpRoot("seed2");
  const base = {
    app: "a", channel: "stable", platform: "win-x64",
    pulseUrl: "http://127.0.0.1:1/p/a/stable/win-x64/pulse.json",
    keys: KEYS, installId: "i1",
  };
  const withSeed = createPayloadClient({ ...base, root: tmpRoot("root2"), seedDir, seedBuild: "seed-1", seedSeq: 0 });
  assert.deepEqual(withSeed.resolve(), { dir: seedDir, build: "seed-1", seq: 0, source: "seed", trial: false });

  const withoutSeed = createPayloadClient({ ...base, root: tmpRoot("root3") });
  assert.throws(() => withoutSeed.resolve(), /no runnable/);
});

test("createPayloadClient refuses missing required config", () => {
  assert.throws(() => createPayloadClient({}), /app/);
});

test("hashTree hashes a directory tree deterministically, posix paths, sorted", async () => {
  const dir = tmpRoot("tree");
  fs.mkdirSync(path.join(dir, "a"));
  fs.writeFileSync(path.join(dir, "a", "2.txt"), "two");
  fs.writeFileSync(path.join(dir, "1.txt"), "one");
  const files = await hashTree(dir);
  assert.deepEqual(files.map((f) => f.p), ["1.txt", "a/2.txt"]);
  assert.equal(files[0].h, sha(Buffer.from("one")));
  assert.equal(files[0].s, 3);
});
