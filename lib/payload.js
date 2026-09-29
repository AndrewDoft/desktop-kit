"use strict";
// Content-addressed payload client — plan §3.2-3.3, §3.10 (frozen API).
//
//   <root>/store/<sha[0:2]>/<sha>     verified blobs (decompressed bytes), read-only
//   <root>/versions/<build>/...       tree materialised by hardlink from the store
//   <root>/versions/<build>/.manifest.json   the manifest that built this tree (for GC/verifyEntry)
//   <root>/versions/<build>/.complete         written last; its presence means the tree is runnable
//   <root>/current.json               {build, seq, previous:{build,seq}|null, trial, trial_started, boots, failures}
//   <root>/bad.json                   {builds:[...]}  — never re-applied
//   <root>/staged.json                {build, seq, manifest, schemaHead} — verified + materialised, not yet active
//   <root>/seed-index.json            {seedBuild, files:[...]} — the seed's hash tree, cached
//
// Every write here is tmp + rename (readJson/writeJsonAtomic reused from ./family.js, itself
// already this pattern). A crash at any point leaves resolve() able to return a runnable tree:
// current if .complete exists, else previous, else the seed.
const fs = require("node:fs");
const fsp = require("node:fs/promises");
const path = require("node:path");
const { createHash } = require("node:crypto");
const { brotliDecompressSync } = require("node:zlib");
const { pipeline } = require("node:stream/promises");
const { EventEmitter } = require("node:events");
const { verifyFeed } = require("./signed-feed.js");
const { readJson, writeJsonAtomic } = require("./family.js");

// Domain-separates the pulse from every other signed document this key might ever sign.
const PULSE_DOMAIN = "desktop-kit-payload-pulse-v1\n";
const PART_SUFFIX = ".partial";
const TEN_MIN_MS = 10 * 60 * 1000;
const DOWNLOAD_CONCURRENCY = 4;

const sha256Hex = (buf) => createHash("sha256").update(buf).digest("hex");

function ensureDir(dir) {
  fs.mkdirSync(dir, { recursive: true });
}

/** Hardlink, falling back to a copy when the store and the destination are not the same
 *  volume/filesystem, or the platform refuses links (EXDEV/EPERM/ENOTSUP). */
function linkOrCopy(src, dest) {
  try {
    fs.linkSync(src, dest);
  } catch (err) {
    if (!["EXDEV", "EPERM", "ENOTSUP"].includes(err.code)) throw err;
    fs.copyFileSync(src, dest);
  }
}

/** Write `buf` to `dest` as tmp + rename, then make it read-only. Used for store blobs: once a
 *  blob is verified it must never change under a build that hardlinks it. */
function commitStoreFile(dest, buf) {
  ensureDir(path.dirname(dest));
  const tmp = `${dest}.tmp`;
  fs.writeFileSync(tmp, buf);
  fs.chmodSync(tmp, 0o444);
  fs.renameSync(tmp, dest);
}

async function hashFile(abs) {
  const hash = createHash("sha256");
  for await (const chunk of fs.createReadStream(abs)) hash.update(chunk);
  return hash.digest("hex");
}

/** The manifest `files` array for `dir`: `{p, h, s, x}` per file, `p` posix-relative, sorted.
 *  Used by the publisher (whole build tree) and by the client (seed mapping). */
async function hashTree(dir) {
  const files = [];
  async function walk(abs, rel) {
    const entries = await fsp.readdir(abs, { withFileTypes: true });
    for (const e of entries) {
      const childAbs = path.join(abs, e.name);
      const childRel = rel ? `${rel}/${e.name}` : e.name;
      if (e.isDirectory()) {
        await walk(childAbs, childRel);
      } else if (e.isFile()) {
        const st = await fsp.stat(childAbs);
        files.push({ p: childRel, h: await hashFile(childAbs), s: st.size, x: (st.mode & 0o111) !== 0 });
      }
    }
  }
  await walk(dir, "");
  files.sort((a, b) => (a.p < b.p ? -1 : a.p > b.p ? 1 : 0));
  return files;
}

/** Run `worker` over `items` with at most `limit` in flight. A rejection propagates (other
 *  in-flight workers are left to settle; not worth cancellation plumbing for a one-shot check()). */
async function pool(items, limit, worker) {
  const it = items[Symbol.iterator]();
  const runners = Array.from({ length: Math.min(limit, items.length) }, async () => {
    for (let n = it.next(); !n.done; n = it.next()) await worker(n.value);
  });
  await Promise.all(runners);
}

/** `.../p/<app>/<channel>/<platform>/pulse.json` -> `.../p` (origin + the shared p/ prefix that
 *  `m/<sha>.json` and `b/<sha>` hang off). */
function urlRoot(pulseUrl, app, channel, platform) {
  const u = new URL(pulseUrl);
  const suffix = `/${app}/${channel}/${platform}/pulse.json`;
  if (!u.pathname.endsWith(suffix)) throw new Error(`pulseUrl does not end with ${suffix}`);
  return u.origin + u.pathname.slice(0, -suffix.length);
}

/** The cryptographically verified pulse document, shape-checked (§3.2). */
function validatePulse(doc, app, channel, platform) {
  if (doc.app !== app || doc.channel !== channel || doc.platform !== platform) {
    throw new Error("the pulse is not for this app/channel/platform");
  }
  if (typeof doc.build !== "string" || !doc.build) throw new Error("the pulse has no build");
  if (!Number.isInteger(doc.seq)) throw new Error("the pulse has no integer seq");
  if (typeof doc.manifest !== "string" || !/^[0-9a-f]{64}$/.test(doc.manifest)) throw new Error("the pulse has no usable manifest hash");
  if (!Number.isInteger(doc.schema_head)) throw new Error("the pulse has no integer schema_head");
  if (!Number.isInteger(doc.shell_min)) throw new Error("the pulse has no integer shell_min");
  return doc;
}

class PayloadClient extends EventEmitter {
  constructor(o = {}) {
    super();
    for (const k of ["app", "channel", "platform", "root", "pulseUrl", "keys", "installId"]) {
      if (!o[k]) throw new Error(`createPayloadClient: ${k} is required`);
    }
    this.app = o.app;
    this.channel = o.channel;
    this.platform = o.platform;
    this.root = o.root;
    this.seedDir = o.seedDir || null;
    this.seedBuild = o.seedBuild || null;
    this.seedSeq = Number.isInteger(o.seedSeq) ? o.seedSeq : null;
    this.pulseUrl = o.pulseUrl;
    this.keys = o.keys;
    this.shellVersion = Number.isInteger(o.shellVersion) ? o.shellVersion : 0;
    this.schemaHead = typeof o.schemaHead === "function" ? o.schemaHead : async () => null;
    this.installId = o.installId;
    this._fetch = o.fetch || ((...a) => fetch(...a));
    this.log = typeof o.log === "function" ? o.log : () => {};
    this._urlRoot = urlRoot(this.pulseUrl, this.app, this.channel, this.platform);
    this._seedIndex = null;
    this._timer = null;
  }

  _currentFile() { return path.join(this.root, "current.json"); }
  _badFile() { return path.join(this.root, "bad.json"); }
  _stagedFile() { return path.join(this.root, "staged.json"); }
  _blobPath(h) { return path.join(this.root, "store", h.slice(0, 2), h); }
  _manifestUrl(h) { return `${this._urlRoot}/m/${h}.json`; }
  _blobUrl(h) { return `${this._urlRoot}/b/${h.slice(0, 2)}/${h}`; }
  _versionDir(build) { return path.join(this.root, "versions", build); }

  /** SYNC, at boot: the best tree that exists on disk right now. Never touches the network. */
  resolve() {
    const current = readJson(this._currentFile());
    if (current) {
      const dir = this._versionDir(current.build);
      if (fs.existsSync(path.join(dir, ".complete"))) {
        return { dir, build: current.build, seq: current.seq, source: "current", trial: !!current.trial };
      }
      if (current.previous) {
        const pdir = this._versionDir(current.previous.build);
        if (fs.existsSync(path.join(pdir, ".complete"))) {
          return { dir: pdir, build: current.previous.build, seq: current.previous.seq, source: "previous", trial: false };
        }
      }
    }
    if (this.seedDir) {
      return { dir: this.seedDir, build: this.seedBuild, seq: this.seedSeq, source: "seed", trial: false };
    }
    throw new Error("no runnable payload tree: no current/previous build, and no seed configured");
  }

  /** Look for a newer, applicable build; fetch, verify and materialise it if there is one.
   *  Never activates it — that is activate()'s job, called when the app decides it is safe. */
  async check() {
    const res = await this._fetch(this.pulseUrl, { cache: "no-store" });
    if (!res.ok) throw new Error(`pulse host answered ${res.status}`);
    const body = await res.json();
    const doc = validatePulse(verifyFeed(body, PULSE_DOMAIN, this.keys, "signed"), this.app, this.channel, this.platform);

    const current = readJson(this._currentFile());
    const curSeq = current ? current.seq : this.seedSeq;
    const curBuild = current ? current.build : this.seedBuild;
    const isRollback = curSeq != null && doc.seq < curSeq && doc.rollback === curBuild;
    if (curSeq != null && doc.seq <= curSeq && !isRollback) return { status: "none" };

    const bad = readJson(this._badFile());
    if (bad && Array.isArray(bad.builds) && bad.builds.includes(doc.build)) return { status: "none" };

    const already = this.staged();
    if (already && already.build === doc.build) return { status: "staged", build: doc.build };

    if (doc.paused) return { status: "paused", build: doc.build };
    if (!this._inRollout(doc)) return { status: "not-in-rollout", build: doc.build };
    if (this.shellVersion < doc.shell_min) return { status: "needs-shell", build: doc.build, reason: `shell ${this.shellVersion} is older than the required ${doc.shell_min}` };
    const head = await this.schemaHead();
    if (head != null && head > doc.schema_head) {
      return { status: "refused", build: doc.build, reason: `local schema ${head} is ahead of the payload's schema_head ${doc.schema_head}` };
    }

    await this._stageBuild(doc);
    this.emit("staged", { build: doc.build, seq: doc.seq });
    return { status: "staged", build: doc.build };
  }

  _inRollout(doc) {
    if (!Number.isInteger(doc.rollout)) return true;
    const bucket = createHash("sha256").update(`${this.installId}${doc.build}`).digest().readUInt32BE(0) % 100;
    return bucket < doc.rollout;
  }

  async _fetchVerified(url, expectedSha) {
    const res = await this._fetch(url, { cache: "no-store" });
    if (!res.ok) throw new Error(`manifest host answered ${res.status}`);
    const buf = Buffer.from(await res.arrayBuffer());
    if (sha256Hex(buf) !== expectedSha) throw new Error("the manifest does not match the hash the pulse named (tampered)");
    return buf;
  }

  async _ensureSeedIndex() {
    if (!this.seedDir) { this._seedIndex = null; return; }
    if (this._seedIndex && this._seedIndex.seedBuild === this.seedBuild) return;
    const cacheFile = path.join(this.root, "seed-index.json");
    const cached = readJson(cacheFile);
    const files = cached && cached.seedBuild === this.seedBuild && Array.isArray(cached.files)
      ? cached.files
      : await hashTree(this.seedDir);
    if (!cached || cached.seedBuild !== this.seedBuild) writeJsonAtomic(cacheFile, { seedBuild: this.seedBuild, files });
    const byHash = new Map();
    for (const f of files) if (!byHash.has(f.h)) byHash.set(f.h, f.p);
    this._seedIndex = { seedBuild: this.seedBuild, byHash };
  }

  async _stageBuild(doc) {
    const manifestBuf = await this._fetchVerified(this._manifestUrl(doc.manifest), doc.manifest);
    const manifest = JSON.parse(manifestBuf.toString("utf8"));
    if (manifest.build !== doc.build || manifest.platform !== this.platform) {
      throw new Error("the manifest does not match the pulse that named it");
    }
    await this._ensureSeedIndex();

    const need = [];
    const seen = new Set();
    for (const f of manifest.files) {
      if (seen.has(f.h)) continue;
      seen.add(f.h);
      if (fs.existsSync(this._blobPath(f.h))) continue;
      const seedRel = this._seedIndex && this._seedIndex.byHash.get(f.h);
      if (seedRel) {
        commitStoreFile(this._blobPath(f.h), fs.readFileSync(path.join(this.seedDir, ...seedRel.split("/"))));
      } else {
        need.push(f.h);
      }
    }
    await pool(need, DOWNLOAD_CONCURRENCY, (h) => this._downloadBlob(h));

    this._materialise(doc.build, manifest);
    writeJsonAtomic(this._stagedFile(), { build: doc.build, seq: doc.seq, manifest: doc.manifest, schemaHead: doc.schema_head });
  }

  /** Stream `h` to `<store>/<h>.partial`, resuming with Range if a previous attempt left bytes
   *  behind, then decompress and verify before it ever reaches the store. */
  async _downloadBlob(h) {
    const dest = this._blobPath(h);
    const part = `${dest}${PART_SUFFIX}`;
    ensureDir(path.dirname(part));
    let start = 0;
    try { start = fs.statSync(part).size; } catch { /* no partial yet */ }

    const res = await this._fetch(this._blobUrl(h), start > 0 ? { headers: { range: `bytes=${start}-` } } : {});
    if (!res.ok) throw new Error(`blob host answered ${res.status} for ${h}`);
    const resumed = start > 0 && res.status === 206;
    if (!resumed) fs.rmSync(part, { force: true });
    const out = fs.createWriteStream(part, { flags: resumed ? "a" : "w" });
    try {
      await pipeline(res.body, out);
    } catch (err) {
      if (!out.closed) { out.destroy(); await new Promise((r) => out.once("close", r)); }
      throw err; // the partial file is left for the next check() to resume
    }

    const compressed = fs.readFileSync(part);
    let raw;
    try {
      raw = brotliDecompressSync(compressed);
    } catch (err) {
      fs.rmSync(part, { force: true });
      throw new Error(`blob ${h} does not decompress (${err.message})`);
    }
    if (sha256Hex(raw) !== h) {
      fs.rmSync(part, { force: true });
      throw new Error(`blob ${h} does not match its hash (tampered)`);
    }
    commitStoreFile(dest, raw);
    fs.rmSync(part, { force: true });
  }

  /** Hardlink (copy fallback) every manifest file from the store into versions/<build>/, then
   *  write .complete last — the only part of this a booting shell needs to see. */
  _materialise(build, manifest) {
    const dir = this._versionDir(build);
    fs.rmSync(dir, { recursive: true, force: true });
    for (const f of manifest.files) {
      const dest = path.join(dir, ...f.p.split("/"));
      ensureDir(path.dirname(dest));
      linkOrCopy(this._blobPath(f.h), dest);
      if (f.x) { try { fs.chmodSync(dest, 0o755); } catch { /* no-op off POSIX */ } }
    }
    writeJsonAtomic(path.join(dir, ".manifest.json"), manifest);
    const marker = path.join(dir, ".complete.tmp");
    fs.writeFileSync(marker, "");
    fs.renameSync(marker, path.join(dir, ".complete"));
  }

  /** The verified, materialised build waiting to be activated, or null. */
  staged() {
    const s = readJson(this._stagedFile());
    if (!s) return null;
    const dir = this._versionDir(s.build);
    if (!fs.existsSync(path.join(dir, ".complete"))) return null;
    return { build: s.build, seq: s.seq, dir, schemaHead: s.schemaHead };
  }

  /** Switch current.json to the staged build as a trial. The caller decides when it is safe. */
  activate() {
    const s = this.staged();
    if (!s) throw new Error("nothing staged to activate");
    const current = readJson(this._currentFile());
    const previous = current
      ? { build: current.build, seq: current.seq }
      : this.seedBuild
        ? { build: this.seedBuild, seq: this.seedSeq }
        : null;
    writeJsonAtomic(this._currentFile(), { build: s.build, seq: s.seq, previous, trial: true, trial_started: Date.now(), boots: 0, failures: [] });
    fs.rmSync(this._stagedFile(), { force: true });
    return { dir: s.dir, build: s.build, previous: previous ? previous.build : null };
  }

  /** Trial -> confirmed. Runs GC (§3.3 step 7: keep current + previous + one more). */
  confirm() {
    const current = readJson(this._currentFile());
    if (!current) throw new Error("nothing active to confirm");
    writeJsonAtomic(this._currentFile(), { ...current, trial: false, trial_started: null, boots: 0, failures: [] });
    this.gc();
  }

  /** One more failed boot toward the 3-strike revert. Returns whether this call tripped it. */
  bootFailed(reason) {
    const current = readJson(this._currentFile());
    if (!current) throw new Error("nothing active to report a boot failure for");
    const now = Date.now();
    const failures = [...(current.failures || []), now].filter((t) => now - t < TEN_MIN_MS);
    if (failures.length >= 3) {
      const r = this.revert(reason || "3 boot failures within 10 minutes");
      return { reverted: true, dir: r.dir };
    }
    writeJsonAtomic(this._currentFile(), { ...current, boots: (current.boots || 0) + 1, failures });
    return { reverted: false, dir: this._versionDir(current.build) };
  }

  /** Immediate revert to previous; the reverted-from build is marked bad (never re-applied). */
  revert(reason) {
    const current = readJson(this._currentFile());
    if (!current || !current.previous) throw new Error("no previous build to revert to");
    const bad = readJson(this._badFile()) || { builds: [] };
    if (!bad.builds.includes(current.build)) bad.builds.push(current.build);
    writeJsonAtomic(this._badFile(), bad);
    this.log(`payload ${current.build} marked bad${reason ? `: ${reason}` : ""}`);

    const { previous } = current;
    writeJsonAtomic(this._currentFile(), { build: previous.build, seq: previous.seq, previous: null, trial: false, trial_started: null, boots: 0, failures: [] });
    const dir = this._versionDir(previous.build);
    return { dir: fs.existsSync(path.join(dir, ".complete")) ? dir : this.seedDir, build: previous.build };
  }

  /** Re-hash `relPaths` in the active build against its recorded manifest; throws on any mismatch. */
  verifyEntry(relPaths) {
    const current = readJson(this._currentFile());
    if (!current) throw new Error("nothing active to verify");
    const dir = this._versionDir(current.build);
    const manifest = readJson(path.join(dir, ".manifest.json"));
    if (!manifest) throw new Error(`no manifest recorded for ${current.build}`);
    const byPath = new Map(manifest.files.map((f) => [f.p, f]));
    for (const rel of relPaths) {
      const entry = byPath.get(rel);
      if (!entry) throw new Error(`${rel} is not part of the ${current.build} manifest`);
      const actual = sha256Hex(fs.readFileSync(path.join(dir, ...rel.split("/"))));
      if (actual !== entry.h) throw new Error(`${rel} does not match the manifest (tampered)`);
    }
  }

  /** Keep the 3 most-recently-touched version trees (current + previous + one more), drop the
   *  rest, and sweep store blobs no kept tree's manifest references. Not in the frozen §3.10
   *  table — GC has no listed entry point there — but §3.3 requires the behaviour, so it also
   *  runs automatically from confirm(). */
  gc() {
    const versionsDir = path.join(this.root, "versions");
    let names;
    try { names = fs.readdirSync(versionsDir); } catch { return; }
    const byMtime = names
      .map((n) => ({ n, t: fs.statSync(path.join(versionsDir, n)).mtimeMs }))
      .sort((a, b) => b.t - a.t);
    const keep = new Set(byMtime.slice(0, 3).map((x) => x.n));
    const referenced = new Set();
    for (const n of keep) {
      const manifest = readJson(path.join(versionsDir, n, ".manifest.json"));
      if (manifest) for (const f of manifest.files) referenced.add(f.h);
    }
    for (const { n } of byMtime) if (!keep.has(n)) fs.rmSync(path.join(versionsDir, n), { recursive: true, force: true });

    let prefixes;
    try { prefixes = fs.readdirSync(path.join(this.root, "store")); } catch { return; }
    for (const prefix of prefixes) {
      const pdir = path.join(this.root, "store", prefix);
      let blobs;
      try { blobs = fs.readdirSync(pdir); } catch { continue; }
      for (const h of blobs) {
        if (h.endsWith(PART_SUFFIX) || referenced.has(h)) continue;
        fs.rmSync(path.join(pdir, h), { force: true });
      }
    }
  }

  /** Interval + on-demand check(); emits "staged" (also emitted per-check by check() itself). */
  start({ everyMs = 120000 } = {}) {
    if (this._timer) return;
    const tick = () => { this.check().catch((err) => this.log(`payload check failed: ${err.message}`)); };
    this._timer = setInterval(tick, everyMs);
    if (this._timer.unref) this._timer.unref();
    tick();
  }

  stop() {
    if (!this._timer) return;
    clearInterval(this._timer);
    this._timer = null;
  }
}

const createPayloadClient = (o) => new PayloadClient(o);

module.exports = { createPayloadClient, hashTree, PULSE_DOMAIN };
