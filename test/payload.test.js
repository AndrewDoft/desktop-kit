"use strict";
const { test } = require("node:test");
const assert = require("node:assert/strict");
const { createServer } = require("node:http");
const { createHash, randomBytes, generateKeyPairSync } = require("node:crypto");
const { brotliCompressSync, constants: zlibConstants } = require("node:zlib");
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
      if (start >= buf.length) { // a real server answers a fully-satisfied range with 416, not 206
        res.writeHead(416, { "content-range": `bytes */${buf.length}` });
        res.end();
        return;
      }
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

  const act = await c.activate();
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
  await c.activate();
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
  await c.activate();
  c.confirm();

  const fxB = fixture({ build: "2.0.0", seq: 2, files: [{ p: "g.bin", raw: randomBytes(16) }] });
  Object.assign(h.files, fxB.registry);
  await c.check();
  await c.activate();
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
  await c.activate();
  assert.throws(() => c.revert("no reason"), /no previous/);
});

test("verifyEntry re-hashes against the recorded manifest; throws on mismatch or unknown path", async (t) => {
  const raw = randomBytes(32);
  const fx = fixture({ build: "1.0.0", seq: 1, files: [{ p: "entry.js", raw }] });
  const h = await serve(fx.registry, t);
  const c = client(h, fx);
  await c.check();
  await c.activate();
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

test("gc keeps exactly {current, previous, staged} read from the JSON files, never by mtime", async (t) => {
  // Reviewer's repro: activate C, then P2 (trial), then stage S1, S2, S3 in turn (each
  // superseding the last, never activated) — S1/S2/S3 are the *most recently written* dirs, so
  // an mtime-based gc would keep them and delete C/P2, leaving resolve() with nothing runnable.
  const h = await serve({}, t);
  const APP = { app: "gcapp", channel: "stable", platform: "win-x64" };
  const c = client(h, APP);
  const build = (n, seq) => {
    const raw = randomBytes(16);
    return fixture({ ...APP, build: `b${n}`, seq, files: [{ p: `f${n}.bin`, raw }] });
  };

  const C = build(1, 1);
  Object.assign(h.files, C.registry);
  await c.check();
  await c.activate();
  c.confirm();

  const P2 = build(2, 2);
  Object.assign(h.files, P2.registry);
  await c.check();
  await c.activate(); // current: P2 (trial), previous: C — not yet confirmed

  for (const [n, seq] of [[3, 3], [4, 4], [5, 5]]) {
    const s = build(n, seq);
    Object.assign(h.files, s.registry);
    await c.check(); // stages S1, then S2 (superseding S1), then S3 (superseding S2)
  }

  c.confirm(); // confirms the P2 trial and runs gc()

  const versions = fs.readdirSync(path.join(c.root, "versions")).sort();
  assert.deepEqual(versions, ["b1", "b2", "b5"].sort(), "current (b2), previous (b1) and staged (b5) survive; b3/b4 (superseded, never activated) do not");
  assert.deepEqual(c.resolve(), { dir: c._versionDir("b2"), build: "b2", seq: 2, source: "current", trial: false });
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

test("hashTree fails loudly on a symlink instead of silently omitting it", async () => {
  const dir = tmpRoot("tree-symlink");
  fs.writeFileSync(path.join(dir, "real.txt"), "x");
  try {
    fs.symlinkSync(path.join(dir, "real.txt"), path.join(dir, "link.txt"));
  } catch (err) {
    if (err.code === "EPERM") return; // no symlink privilege on this runner; nothing to assert
    throw err;
  }
  await assert.rejects(hashTree(dir), /symlink/);
});

test("a decompression bomb is rejected before the oversized buffer is produced, not after (finding 2)", async (t) => {
  const declared = randomBytes(32); // the legitimate small file the manifest names
  const bombRaw = Buffer.alloc(5 * 1024 * 1024); // 5 MiB of zeros: trivially compressible
  const bomb = brotliCompressSync(bombRaw, { params: { [zlibConstants.BROTLI_PARAM_QUALITY]: 5 } });
  const fx = fixture({ build: "bomb-1.0.0", seq: 1, files: [{ p: "f.bin", raw: declared }] });
  const blobKey = Object.keys(fx.registry).find((k) => k.startsWith("p/b/"));
  fx.registry[blobKey] = bomb; // the server answers with a bomb for whatever hash the client asked
  const h = await serve(fx.registry, t);
  const c = client(h, fx);
  // maxOutputLength aborts decompression at the declared size, so the error is a decompress
  // failure, not the later hash-mismatch that would follow a *completed* 5 MiB decompression.
  await assert.rejects(c.check(), /does not decompress/);
  assert.equal(c.staged(), null);
  assert.equal(fs.existsSync(path.join(c.root, "store", sha(declared).slice(0, 2), sha(declared))), false);
});

test("a pulse backdated before an already-seen `issued` is refused (freeze protection)", async (t) => {
  const fx1 = fixture({ build: "fr1", seq: 1, files: [{ p: "f.bin", raw: randomBytes(8) }] });
  const h = await serve(fx1.registry, t);
  const c = client(h, fx1);
  await c.check();
  await c.activate();
  c.confirm();

  const fx2 = fixture({ build: "fr2", seq: 2, files: [{ p: "f.bin", raw: randomBytes(8) }] });
  fx2.registry["p/app1/stable/win-x64/pulse.json"].signed.issued = "2000-01-01T00:00:00.000Z"; // backdated
  fx2.registry["p/app1/stable/win-x64/pulse.json"].signature = signDocument(PULSE_DOMAIN, fx2.registry["p/app1/stable/win-x64/pulse.json"].signed, PEM, "k1");
  Object.assign(h.files, fx2.registry);
  const r = await c.check();
  assert.equal(r.status, "refused");
  assert.equal(c.resolve().build, "fr1");
});

test("concurrent check() calls share one in-flight request instead of racing onto the same .partial", async (t) => {
  const fx = fixture({ build: "race-1.0.0", seq: 1, files: [{ p: "f.bin", raw: randomBytes(4096) }] });
  const h = await serve(fx.registry, t);
  const c = client(h, fx);
  const [r1, r2] = await Promise.all([c.check(), c.check()]);
  assert.equal(r1.status, "staged");
  assert.deepEqual(r1, r2, "both callers observe the same single check()");
  const pulseHits = h.hits.filter((n) => n.endsWith("pulse.json"));
  assert.equal(pulseHits.length, 1, "only one request went out, not one per caller");
});

test("an oversized compressed download is aborted before it fully lands on disk (finding 2, download cap)", async (t) => {
  const declared = randomBytes(32); // the legitimate small file the manifest names
  const oversized = randomBytes(2 * 1024 * 1024); // incompressible: brotli cannot shrink this below the cap
  const fx = fixture({ build: "overrun-1.0.0", seq: 1, files: [{ p: "f.bin", raw: declared }] });
  const blobKey = Object.keys(fx.registry).find((k) => k.startsWith("p/b/"));
  fx.registry[blobKey] = oversized; // served uncompressed on purpose: still way past the 32-byte + 1 MiB cap
  const h = await serve(fx.registry, t);
  const c = client(h, fx);
  await assert.rejects(c.check(), /exceeds the download size cap/);
  assert.equal(c.staged(), null);
});

test("a pulse naming the currently-running build, even at a higher seq, is refused and never re-materialised (finding 3)", async (t) => {
  const raw1 = randomBytes(16);
  const fx1 = fixture({ build: "same-1.0.0", seq: 1, files: [{ p: "app.js", raw: raw1 }] });
  const h = await serve(fx1.registry, t);
  const c = client(h, fx1);
  await c.check();
  await c.activate();
  c.confirm();
  assert.equal(c.resolve().build, "same-1.0.0");

  const raw2 = randomBytes(16); // different content, SAME build string, higher seq — no rollback field
  const fx2 = fixture({ build: "same-1.0.0", seq: 2, files: [{ p: "app.js", raw: raw2 }] });
  Object.assign(h.files, fx2.registry);
  const r = await c.check();
  assert.equal(r.status, "refused");
  assert.deepEqual(fs.readFileSync(path.join(c.resolve().dir, "app.js")), raw1, "the running tree's file is untouched");
});

test("a pulse naming the previous build without a signed rollback is refused (finding 3)", async (t) => {
  const fx1 = fixture({ build: "p1", seq: 1, files: [{ p: "f.bin", raw: randomBytes(8) }] });
  const h = await serve(fx1.registry, t);
  const c = client(h, fx1);
  await c.check();
  await c.activate();
  c.confirm();

  const fx2 = fixture({ build: "p2", seq: 2, files: [{ p: "f.bin", raw: randomBytes(8) }] });
  Object.assign(h.files, fx2.registry);
  await c.check();
  await c.activate(); // current: p2, previous: p1

  const spoof = fixture({ build: "p1", seq: 3, files: [{ p: "evil.bin", raw: randomBytes(8) }] }); // build == previous, no rollback field
  Object.assign(h.files, spoof.registry);
  const r = await c.check();
  assert.equal(r.status, "refused");
});

test("verifyEntry and resolve() re-verify the signed pulse + manifest.raw, not a re-serialised copy — editing both together no longer passes (finding 4)", async (t) => {
  const raw = randomBytes(32);
  const fx = fixture({ build: "tamper-1.0.0", seq: 1, files: [{ p: "boot.js", raw }] });
  const h = await serve(fx.registry, t);
  const c = client(h, fx);
  await c.check();
  await c.activate();
  assert.doesNotThrow(() => c.verifyEntry(["boot.js"]));
  const dir = c.resolve().dir;

  // an attacker with directory-write (but not the signing key) edits the file AND forges a
  // consistent-looking manifest.raw naming the new bytes' real hash.
  const evil = randomBytes(32);
  fs.chmodSync(path.join(dir, "boot.js"), 0o666);
  fs.writeFileSync(path.join(dir, "boot.js"), evil);
  const forged = { ...fx.manifest, files: fx.manifest.files.map((f) => (f.p === "boot.js" ? { ...f, h: sha(evil) } : f)) };
  fs.writeFileSync(path.join(dir, ".manifest.raw"), JSON.stringify(forged));

  assert.throws(() => c.verifyEntry(["boot.js"]), /no verified manifest/);
  assert.throws(() => c.resolve(), /no runnable payload tree/, "resolve() fails closed rather than trusting the forged tree");
});

test("a poisoned store blob is re-hashed and healed, not reused, when a later build shares its hash (finding 4 / 7)", async (t) => {
  const raw = randomBytes(16);
  const fx1 = fixture({ build: "heal-1.0.0", seq: 1, files: [{ p: "shared.bin", raw }] });
  const h = await serve(fx1.registry, t);
  const c = client(h, fx1);
  await c.check();
  await c.activate();
  c.confirm();

  // simulate corruption of the store blob (e.g. a hardlinked tree file rewritten in place, the
  // way writing through a hardlink corrupts every tree sharing that inode).
  const blobPath = path.join(c.root, "store", sha(raw).slice(0, 2), sha(raw));
  fs.chmodSync(blobPath, 0o666);
  fs.writeFileSync(blobPath, randomBytes(16));

  const fx2 = fixture({ build: "heal-2.0.0", seq: 2, files: [{ p: "shared.bin", raw }, { p: "new.bin", raw: randomBytes(8) }] });
  Object.assign(h.files, fx2.registry);
  await c.check();
  assert.deepEqual(fs.readFileSync(path.join(c.staged().dir, "shared.bin")), raw, "the poisoned blob was detected and re-fetched, not reused");
});

test("a rollback lowers current.seq but never the replay-protection floor (finding 5)", async (t) => {
  const h = await serve({}, t);
  const fx9 = fixture({ build: "B9", seq: 9, files: [{ p: "f.bin", raw: randomBytes(16) }] });
  Object.assign(h.files, fx9.registry);
  const c = client(h, fx9);
  await c.check();
  await c.activate();
  c.confirm();

  // a rollback to a fictitious earlier build B8 at a LOWER seq than B9 — §3.2 allows this shape
  // as long as it validly names the current build.
  const fx8 = fixture({ build: "B8", seq: 8, files: [{ p: "g.bin", raw: randomBytes(16) }], rollback: "B9" });
  Object.assign(h.files, fx8.registry);
  assert.equal((await c.check()).status, "staged");
  await c.activate();
  c.confirm();
  assert.equal(c.resolve().build, "B8");
  assert.equal(JSON.parse(fs.readFileSync(path.join(c.root, "current.json"), "utf8")).seq, 8);

  // replaying the ORIGINAL, validly-signed B9 pulse must be refused even though 9 > current.seq(8)
  Object.assign(h.files, fx9.registry);
  assert.equal((await c.check()).status, "none", "the old B9 pulse is refused even though 9 > current.seq 8");
  assert.equal(c.resolve().build, "B8");
});

test("a genuine rollback to a build still sitting as `previous` never rewrites its intact version dir (finding 3 idempotence)", async (t) => {
  const fx1 = fixture({ build: "r1", seq: 1, files: [{ p: "f.bin", raw: randomBytes(8) }] });
  const h = await serve(fx1.registry, t);
  const c = client(h, fx1);
  await c.check();
  await c.activate();
  c.confirm(); // current: r1

  const fx2 = fixture({ build: "r2", seq: 2, files: [{ p: "f.bin", raw: randomBytes(8) }] });
  Object.assign(h.files, fx2.registry);
  await c.check();
  await c.activate(); // current: r2, previous: r1 (still on disk, .complete intact)

  const before = fs.statSync(path.join(c._versionDir("r1"), "f.bin"));
  const rb = fixture({ build: "r1", seq: 3, files: [{ p: "f.bin", raw: randomBytes(8) }], rollback: "r2" });
  Object.assign(h.files, rb.registry);
  const r = await c.check();
  assert.equal(r.status, "staged");
  const after = fs.statSync(path.join(c._versionDir("r1"), "f.bin"));
  assert.equal(before.ino, after.ino, "the intact previous tree was never rematerialised");
});

test("a pulse at the same seq as one already accepted, but naming different content, is refused as a seq collision (finding 5)", async (t) => {
  const fx = fixture({ build: "coll-1.0.0", seq: 4, files: [{ p: "f.bin", raw: randomBytes(8) }] });
  const h = await serve(fx.registry, t);
  const c = client(h, fx);
  await c.check();
  await c.activate();
  c.confirm();

  // same seq, DIFFERENT build/content — never a legitimate resign, must not be accepted
  const collision = fixture({ build: "coll-1.0.0-evil", seq: 4, files: [{ p: "f.bin", raw: randomBytes(8) }] });
  Object.assign(h.files, collision.registry);
  assert.equal((await c.check()).status, "none");
  assert.equal(c.resolve().build, "coll-1.0.0");
});

test("a manifest entry escaping the tree is refused before touching the filesystem (finding 6)", async (t) => {
  const escaped = path.join(os.tmpdir(), "kit-pay-escaped.txt");
  fs.rmSync(escaped, { force: true });
  t.after(() => fs.rmSync(escaped, { force: true }));
  const raw = randomBytes(8);
  const fx = fixture({ build: "esc-1.0.0", seq: 1, files: [{ p: "../../../kit-pay-escaped.txt", raw }] });
  const h = await serve(fx.registry, t);
  const c = client(h, fx);
  await assert.rejects(c.check(), /invalid manifest path/);
  assert.equal(fs.existsSync(escaped), false);
});

test("a build id of '..' is refused before it can be used to wipe the root (finding 6)", async (t) => {
  const fx = fixture({ build: "..", seq: 1, files: [{ p: "f.bin", raw: randomBytes(8) }] });
  const h = await serve(fx.registry, t);
  const c = client(h, fx);
  await assert.rejects(c.check(), /invalid build/);
});

test("a manifest file hash that is not 64 lowercase hex chars is refused, even inside an otherwise validly-signed pulse (finding 6)", async (t) => {
  const raw = randomBytes(8);
  const build = "badhash-1.0.0";
  const manifest = { build, platform: "win-x64", files: [{ p: "f.bin", h: "not-a-hash", s: raw.length, x: false }], entry: {} };
  const manifestBytes = Buffer.from(JSON.stringify(manifest));
  const manifestHash = sha(manifestBytes);
  const doc = {
    app: "app1", channel: "stable", platform: "win-x64", build, seq: 1, manifest: manifestHash,
    shell_min: 0, schema_head: 0, rollout: 100, paused: false, issued: new Date().toISOString(),
  };
  const registry = {
    "p/app1/stable/win-x64/pulse.json": { signed: doc, signature: signDocument(PULSE_DOMAIN, doc, PEM, "k1") },
    [`p/m/${manifestHash}.json`]: manifestBytes,
  };
  const h = await serve(registry, t);
  const c = client(h, { app: "app1", channel: "stable", platform: "win-x64" });
  await assert.rejects(c.check(), /invalid hash/);
});

test("a stale or edited seed-index entry is re-hashed before its bytes are trusted into the store (finding 7)", async (t) => {
  const real = randomBytes(64);
  const seedDir = tmpRoot("seed3");
  fs.writeFileSync(path.join(seedDir, "unchanged.bin"), real);

  const fx = fixture({ build: "seedcheck-1.0.0", seq: 1, files: [{ p: "unchanged.bin", raw: real }] });
  const h = await serve(fx.registry, t);
  const c = client(h, fx, { seedDir, seedBuild: "seed-9", seedSeq: 1 });

  await c._ensureSeedIndex(); // populate + cache seed-index.json against the real bytes
  fs.writeFileSync(path.join(seedDir, "unchanged.bin"), randomBytes(64)); // seed file edited after indexing

  const r = await c.check();
  assert.equal(r.status, "staged");
  assert.deepEqual(fs.readFileSync(path.join(c.staged().dir, "unchanged.bin")), real, "the edited seed bytes were rejected; the real content came from the network instead");
  assert.ok(h.hits.filter((n) => n.startsWith("p/b/")).length > 0, "fell back to a network fetch once the seed bytes failed to re-hash");
});

test("a stale full-size .partial gets a 416 on resume; the client drops it and retries with a plain GET (finding 8)", async (t) => {
  const raw = randomBytes(4096);
  const fx = fixture({ build: "wedge-1.0.0", seq: 1, files: [{ p: "f.bin", raw }] });
  const h = await serve(fx.registry, t);
  const blobKey = Object.keys(fx.registry).find((k) => k.startsWith("p/b/"));
  const c = client(h, fx);

  const hash = sha(raw);
  const partDir = path.join(c.root, "store", hash.slice(0, 2));
  fs.mkdirSync(partDir, { recursive: true });
  fs.writeFileSync(path.join(partDir, `${hash}.partial`), fx.registry[blobKey]); // already full-size

  const r = await c.check();
  assert.equal(r.status, "staged");
  assert.deepEqual(fs.readFileSync(path.join(c.staged().dir, "f.bin")), raw);
});

test("gc sweeps .partial files older than a day but leaves fresh ones alone (finding 8)", async (t) => {
  const h = await serve({}, t);
  const c = client(h, { app: "partapp", channel: "stable", platform: "win-x64" });
  const oldPart = path.join(c.root, "store", "ab", "ab-old.partial");
  const freshPart = path.join(c.root, "store", "ab", "ab-fresh.partial");
  fs.mkdirSync(path.dirname(oldPart), { recursive: true });
  fs.writeFileSync(oldPart, "x");
  fs.writeFileSync(freshPart, "x");
  const oldTime = (Date.now() - 25 * 60 * 60 * 1000) / 1000;
  fs.utimesSync(oldPart, oldTime, oldTime);

  c.gc();
  assert.equal(fs.existsSync(oldPart), false, "a day-old .partial is swept");
  assert.equal(fs.existsSync(freshPart), true, "a fresh .partial is left for the next resume");
});

test("activate() recovers from a stale staged.json that already equals current, without corrupting previous (finding 9)", async (t) => {
  const fx = fixture({ build: "crash-1.0.0", seq: 1, files: [{ p: "f.bin", raw: randomBytes(8) }] });
  const h = await serve(fx.registry, t);
  const c = client(h, fx);
  await c.check();
  await c.activate();

  // simulate a crash between writing current.json and clearing staged.json
  fs.writeFileSync(path.join(c.root, "staged.json"), JSON.stringify({ build: "crash-1.0.0", seq: 1, manifest: fx.doc.manifest, schemaHead: 0, shellMin: 0 }));

  const act = await c.activate();
  assert.equal(act.build, "crash-1.0.0");
  assert.notEqual(act.previous, "crash-1.0.0", "previous must never equal the build being activated");
  assert.equal(c.staged(), null, "the stale staged marker is cleared");
});

test("re-signing a staged build's pulse as paused unstages it without restaging (finding 9 / v0.2.1 interaction)", async (t) => {
  const files = [{ p: "f.bin", raw: randomBytes(8) }];
  const fx = fixture({ build: "pauseme-1.0.0", seq: 5, files });
  const h = await serve(fx.registry, t);
  const c = client(h, fx);
  assert.equal((await c.check()).status, "staged");
  assert.ok(c.staged());

  const fxPaused = fixture({ build: "pauseme-1.0.0", seq: 5, files, paused: true }); // same build+manifest, only paused/issued differ
  Object.assign(h.files, fxPaused.registry);
  const r = await c.check();
  assert.equal(r.status, "paused");
  assert.equal(c.staged(), null, "the already-staged build is unstaged, not left stale");
});

test("activate() refuses a staged build whose shell_min it no longer satisfies, but leaves it staged to retry once the shell catches up (finding 9)", async (t) => {
  const fx = fixture({ build: "gate-1.0.0", seq: 1, files: [{ p: "f.bin", raw: randomBytes(8) }], shellMin: 5 });
  const h = await serve(fx.registry, t);
  const c = createPayloadClient({
    app: fx.app, channel: fx.channel, platform: fx.platform, root: tmpRoot("root"),
    pulseUrl: `${h.base}p/${fx.app}/${fx.channel}/${fx.platform}/pulse.json`,
    keys: KEYS, installId: "install-1", shellVersion: 5,
  });
  assert.equal((await c.check()).status, "staged");
  c.shellVersion = 4; // the shell was rolled back locally after staging
  await assert.rejects(c.activate(), /shell 4 is older/);
  assert.ok(c.staged(), "shell_min is a not-yet-applicable gate, not invalid content — stays staged");

  c.shellVersion = 5; // the shell catches back up
  const act = await c.activate();
  assert.equal(act.build, "gate-1.0.0");
});

test("activate() refuses and unstages a staged build that was marked bad since it was staged (finding 9)", async (t) => {
  const fx1 = fixture({ build: "p1", seq: 1, files: [{ p: "f.bin", raw: randomBytes(8) }] });
  const h = await serve(fx1.registry, t);
  const c = client(h, fx1);
  await c.check();
  await c.activate();
  c.confirm();

  const fx2 = fixture({ build: "p2", seq: 2, files: [{ p: "f.bin", raw: randomBytes(8) }] });
  Object.assign(h.files, fx2.registry);
  await c.check(); // p2 staged

  // p2 gets bad-listed by an unrelated event before it is ever activated (e.g. a manual mark)
  fs.writeFileSync(path.join(c.root, "bad.json"), JSON.stringify({ builds: ["p2"] }));
  await assert.rejects(c.activate(), /now marked bad/);
  assert.equal(c.staged(), null, "a genuinely bad-listed build is dropped, not retried");
});

test("path/build/hash validators (finding 6) reject Windows-hostile and colliding names", () => {
  const { validateBuild, validateRelPath, validateHash, validateManifest } = require("..");
  assert.throws(() => validateBuild(""), /invalid build/);
  assert.throws(() => validateBuild("a".repeat(65)), /invalid build/);
  assert.throws(() => validateBuild(".."), /invalid build/);
  assert.doesNotThrow(() => validateBuild("0.3.117"));

  for (const bad of ["/abs.txt", "C:\\x", "a/../b", "a/./b", "a:b", "con.txt", "LPT1", "trailing.", "trailing "]) {
    assert.throws(() => validateRelPath(bad), undefined, `expected ${bad} to be rejected`);
  }
  assert.throws(() => validateRelPath(".complete"), /reserved control file/);
  assert.throws(() => validateRelPath(".manifest.raw"), /reserved control file/);
  assert.doesNotThrow(() => validateRelPath("a/b/c.txt"));

  assert.throws(() => validateHash("nothex"), /invalid hash/);
  assert.doesNotThrow(() => validateHash("0".repeat(64)));

  assert.throws(() => validateManifest({ files: [{ p: "A.txt", h: "0".repeat(64), s: 1 }, { p: "a.txt", h: "1".repeat(64), s: 1 }] }), /case-insensitive/);
});
