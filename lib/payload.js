"use strict";
// Content-addressed payload client — plan §3.2-3.3, §3.10 (frozen API).
//
//   <root>/store/<sha[0:2]>/<sha>     verified blobs (decompressed bytes), read-only
//   <root>/versions/<build>/...       tree materialised by hardlink from the store
//   <root>/versions/<build>/.pulse.json     the raw signed pulse bytes that named this build
//   <root>/versions/<build>/.manifest.raw   the raw manifest bytes (hash-bound to .pulse.json)
//   <root>/versions/<build>/.complete       written last; its presence means the tree is runnable
//   <root>/current.json               {build, seq, previous:{build,seq}|null, trial, trial_started,
//                                       boots, failures, high_seq, high_seq_build, high_seq_manifest,
//                                       high_seq_issued}
//   <root>/bad.json                   {builds:[...]}  — never re-applied
//   <root>/staged.json                {build, seq, manifest, schemaHead, shellMin} — verified +
//                                       materialised, not yet active
//   <root>/seed-index.json            {seedBuild, files:[...]} — the seed's hash tree, cached
//
// Every write here is tmp + rename, fsync'd (family.js's writeJsonAtomic / this file's
// commitStoreFile / _materialise). A crash at any point leaves resolve() able to return a
// runnable, cryptographically-verified tree: current if it re-verifies, else previous, else seed.
//
// current.json's `high_seq*` fields are a floor that only ever moves forward, independent of
// `seq` (which moves backward on a legitimate rollback). Replaying an old, validly-signed pulse
// can never re-stage a build once a higher seq has been seen, even across a rollback.
const fs = require("node:fs");
const fsp = require("node:fs/promises");
const path = require("node:path");
const { createHash, randomBytes } = require("node:crypto");
const { brotliDecompressSync } = require("node:zlib");
const { pipeline } = require("node:stream/promises");
const { Transform } = require("node:stream");
const { EventEmitter } = require("node:events");
const { verifyFeed } = require("./signed-feed.js");
const { readJson, writeJsonAtomic, fsyncFile, fsyncDir } = require("./family.js");

// Domain-separates the pulse from every other signed document this key might ever sign.
const PULSE_DOMAIN = "desktop-kit-payload-pulse-v1\n";
const PART_SUFFIX = ".partial";
const TEN_MIN_MS = 10 * 60 * 1000;
const ONE_DAY_MS = 24 * 60 * 60 * 1000;
const ONE_MIB = 1024 * 1024;
const MAX_MANIFEST_BYTES = 64 * ONE_MIB;
const MAX_MANIFEST_FILES = 200_000;
const DOWNLOAD_CONCURRENCY = 4;

const BUILD_RE = /^[0-9A-Za-z._-]{1,64}$/;
const HASH_RE = /^[0-9a-f]{64}$/;
const RESERVED_WIN_NAME = /^(CON|PRN|AUX|NUL|COM[1-9]|LPT[1-9])(\..*)?$/i;
const RESERVED_CONTROL_FILES = new Set([".complete", ".manifest.json", ".pulse.json", ".manifest.raw"]);

const sha256Hex = (buf) => createHash("sha256").update(buf).digest("hex");

/** `build` must be a short, filesystem-safe token — it becomes a directory name. */
function validateBuild(build) {
  if (typeof build !== "string" || !BUILD_RE.test(build) || build === "." || build === "..") {
    throw new Error(`invalid build: ${JSON.stringify(build)}`);
  }
  return build;
}

function validateHash(h) {
  if (typeof h !== "string" || !HASH_RE.test(h)) throw new Error(`invalid hash: ${JSON.stringify(h)}`);
  return h;
}

/** A manifest file path must be relative, forward-slash, and unable to escape or collide:
 *  no `..`/`.`/empty segments, no drive letters or backslashes, no `:` (ADS), no Windows
 *  reserved device names, no trailing dot/space, and never one of the tree's own control files. */
function validateRelPath(p) {
  if (typeof p !== "string" || !p) throw new Error(`invalid manifest path: ${JSON.stringify(p)}`);
  if (p.includes("\\")) throw new Error(`invalid manifest path (backslash): ${p}`);
  if (p.startsWith("/") || /^[A-Za-z]:/.test(p)) throw new Error(`invalid manifest path (absolute or drive letter): ${p}`);
  if (p.includes(":")) throw new Error(`invalid manifest path (colon / ADS): ${p}`);
  const segments = p.split("/");
  for (const seg of segments) {
    if (seg === "" || seg === "." || seg === "..") throw new Error(`invalid manifest path segment: ${p}`);
    if (/[ .]$/.test(seg)) throw new Error(`invalid manifest path (trailing dot/space): ${p}`);
    if (RESERVED_WIN_NAME.test(seg)) throw new Error(`invalid manifest path (reserved device name): ${p}`);
  }
  if (RESERVED_CONTROL_FILES.has(segments[segments.length - 1])) {
    throw new Error(`invalid manifest path (reserved control file): ${p}`);
  }
  return p;
}

/** Validates every file entry (path, hash, size) and rejects case-insensitive path collisions
 *  (distinct on a case-sensitive store, the same file on Windows/macOS default volumes) and
 *  absurd file counts, before any of it is trusted to walk the filesystem. */
function validateManifest(manifest) {
  if (!manifest || typeof manifest !== "object" || !Array.isArray(manifest.files)) {
    throw new Error("manifest has no files array");
  }
  if (manifest.files.length > MAX_MANIFEST_FILES) {
    throw new Error(`manifest has too many files (${manifest.files.length} > ${MAX_MANIFEST_FILES})`);
  }
  const seen = new Set();
  for (const f of manifest.files) {
    validateRelPath(f.p);
    validateHash(f.h);
    if (!Number.isInteger(f.s) || f.s < 0) throw new Error(`invalid file size for ${f.p}`);
    const key = f.p.toLowerCase();
    if (seen.has(key)) throw new Error(`duplicate path (case-insensitive collision): ${f.p}`);
    seen.add(key);
  }
  return manifest;
}

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

/** Write `buf` to `dest` as tmp + rename, fsync'd, then read-only. Store blobs are never
 *  chmod'd again after this — `_ensureExecutable` sets exec bits on the store blob itself,
 *  before it is ever linked into a tree, never on a tree's hardlink afterwards. */
function commitStoreFile(dest, buf) {
  ensureDir(path.dirname(dest));
  const tmp = `${dest}.tmp`;
  fs.writeFileSync(tmp, buf);
  fs.chmodSync(tmp, 0o444);
  fsyncFile(tmp);
  fs.renameSync(tmp, dest);
  fsyncDir(path.dirname(dest));
}

async function hashFile(abs) {
  const hash = createHash("sha256");
  for await (const chunk of fs.createReadStream(abs)) hash.update(chunk);
  return hash.digest("hex");
}

/** The manifest `files` array for `dir`: `{p, h, s, x}` per file, `p` posix-relative, sorted.
 *  Used by the publisher (whole build tree) and by the client (seed mapping). A symlink is
 *  refused rather than silently omitted — a payload tree with an unhashed, unshipped file is
 *  a worse failure than a loud one at build/seed time. */
async function hashTree(dir) {
  const files = [];
  async function walk(abs, rel) {
    const entries = await fsp.readdir(abs, { withFileTypes: true });
    for (const e of entries) {
      const childAbs = path.join(abs, e.name);
      const childRel = rel ? `${rel}/${e.name}` : e.name;
      if (e.isSymbolicLink()) {
        throw new Error(`symlink not supported in a payload tree: ${childRel}`);
      } else if (e.isDirectory()) {
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
  validateBuild(doc.build);
  if (!Number.isInteger(doc.seq)) throw new Error("the pulse has no integer seq");
  validateHash(doc.manifest);
  if (!Number.isInteger(doc.schema_head)) throw new Error("the pulse has no integer schema_head");
  if (!Number.isInteger(doc.shell_min)) throw new Error("the pulse has no integer shell_min");
  if (doc.rollback !== undefined) validateBuild(doc.rollback);
  return doc;
}

/** A Transform that throws once more than `limit` bytes have passed through — the compressed-
 *  download half of the decompression-bomb defence (the other half is maxOutputLength below). */
function sizeCap(limit, label) {
  let total = 0;
  return new Transform({
    transform(chunk, _enc, cb) {
      total += chunk.length;
      if (total > limit) {
        const err = new Error(`${label} exceeds the download size cap (${limit} bytes)`);
        err.isCapViolation = true;
        return cb(err);
      }
      cb(null, chunk);
    },
  });
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
    // async () => integer|null. An app WITH a schema (Masora) must never return null — null means
    // "this app has no schema" (Zevet/Voice) and skips the schema_head guard entirely. A throw
    // here refuses the pulse: check()/activate() are awaiting it and let the rejection propagate.
    this.schemaHead = typeof o.schemaHead === "function" ? o.schemaHead : async () => null;
    this.installId = o.installId;
    this._fetch = o.fetch || ((...a) => fetch(...a));
    this.log = typeof o.log === "function" ? o.log : () => {};
    this._urlRoot = urlRoot(this.pulseUrl, this.app, this.channel, this.platform);
    this._seedIndex = null;
    this._timer = null;
    this._checkPromise = null;
  }

  _currentFile() { return path.join(this.root, "current.json"); }
  _badFile() { return path.join(this.root, "bad.json"); }
  _stagedFile() { return path.join(this.root, "staged.json"); }
  _blobPath(h) { return path.join(this.root, "store", h.slice(0, 2), h); }
  _manifestUrl(h) { return `${this._urlRoot}/m/${h}.json`; }
  _blobUrl(h) { return `${this._urlRoot}/b/${h.slice(0, 2)}/${h}`; }
  _versionDir(build) { return path.join(this.root, "versions", build); }

  /** current.json, or a stub carrying no build — used so high_seq can be recorded before any
   *  build has ever been activated (a fresh install with only a seed). */
  _currentOrStub() {
    return readJson(this._currentFile()) || { build: null, seq: null, previous: null, trial: false, trial_started: null, boots: 0, failures: [] };
  }

  /** The replay-protection floor: the highest seq ever accepted, and the build/manifest/issued
   *  it named. Falls back to the seed's build/seq with no recorded manifest (meaning: nothing
   *  real has been accepted yet, so an equal-seq pulse is a first acceptance, not a resign). */
  _highSeqInfo() {
    const current = readJson(this._currentFile());
    if (current && current.high_seq != null) {
      return { seq: current.high_seq, build: current.high_seq_build, manifest: current.high_seq_manifest, issued: current.high_seq_issued };
    }
    return { seq: this.seedSeq, build: this.seedBuild, manifest: null, issued: null };
  }

  /** The floor only ever moves forward: a lower or equal seq never overwrites it, so a
   *  rollback (which lowers `current.seq`) can never lower the replay-protection floor. */
  _recordHighSeq(doc) {
    const current = this._currentOrStub();
    if (current.high_seq != null && doc.seq <= current.high_seq) return;
    writeJsonAtomic(this._currentFile(), {
      ...current,
      high_seq: doc.seq, high_seq_build: doc.build, high_seq_manifest: doc.manifest, high_seq_issued: doc.issued,
    });
  }

  _addBad(build, reason) {
    const bad = readJson(this._badFile()) || { builds: [] };
    if (!bad.builds.includes(build)) bad.builds.push(build);
    writeJsonAtomic(this._badFile(), bad);
    this.log(`payload ${build} marked bad${reason ? `: ${reason}` : ""}`);
  }

  _unstage() {
    fs.rmSync(this._stagedFile(), { force: true });
  }

  /** SYNC, at boot: the best tree that exists on disk right now and re-verifies. Never touches
   *  the network. A tree that fails to re-verify (§3.9 tamper defence, finding 4) is treated
   *  exactly like an incomplete one: fall to previous, then the seed. */
  resolve() {
    const current = readJson(this._currentFile());
    if (current && current.build) {
      const dir = this._versionDir(current.build);
      if (this._loadVerifiedTree(dir)) {
        return { dir, build: current.build, seq: current.seq, source: "current", trial: !!current.trial };
      }
      if (current.previous) {
        const pdir = this._versionDir(current.previous.build);
        if (this._loadVerifiedTree(pdir)) {
          return { dir: pdir, build: current.previous.build, seq: current.previous.seq, source: "previous", trial: false };
        }
      }
    }
    if (this.seedDir) {
      return { dir: this.seedDir, build: this.seedBuild, seq: this.seedSeq, source: "seed", trial: false };
    }
    throw new Error("no runnable payload tree: no current/previous build, and no seed configured");
  }

  /** Re-verifies `dir`'s `.pulse.json` signature and `.manifest.raw` hash-binding to it — never
   *  a re-serialised copy (finding 4). Returns `{pulseDoc, manifest}` or null on any failure
   *  (missing `.complete`, missing/corrupt files, bad signature, hash mismatch). */
  _loadVerifiedTree(dir) {
    if (!fs.existsSync(path.join(dir, ".complete"))) return null;
    try {
      const pulseBody = JSON.parse(fs.readFileSync(path.join(dir, ".pulse.json"), "utf8"));
      const pulseDoc = verifyFeed(pulseBody, PULSE_DOMAIN, this.keys, "signed");
      const manifestRaw = fs.readFileSync(path.join(dir, ".manifest.raw"));
      if (sha256Hex(manifestRaw) !== pulseDoc.manifest) return null;
      return { pulseDoc, manifest: JSON.parse(manifestRaw.toString("utf8")) };
    } catch {
      return null;
    }
  }

  /** Look for a newer, applicable build; fetch, verify and materialise it if there is one.
   *  Never activates it — that is activate()'s job, called when the app decides it is safe.
   *  Single-flight: concurrent callers share one in-flight check (avoids two downloads racing
   *  onto the same `.partial`). */
  check() {
    if (this._checkPromise) return this._checkPromise;
    this._checkPromise = this._checkImpl().finally(() => { this._checkPromise = null; });
    return this._checkPromise;
  }

  async _checkImpl() {
    const res = await this._fetch(this.pulseUrl, { cache: "no-store" });
    if (!res.ok) throw new Error(`pulse host answered ${res.status}`);
    const rawPulse = await res.text();
    let body;
    try { body = JSON.parse(rawPulse); } catch { throw new Error("the pulse is not valid JSON"); }
    const doc = validatePulse(verifyFeed(body, PULSE_DOMAIN, this.keys, "signed"), this.app, this.channel, this.platform);

    const current = readJson(this._currentFile());
    const curBuild = current && current.build ? current.build : null;
    const previousBuild = current && current.previous ? current.previous.build : null;
    const high = this._highSeqInfo();
    const isRollback = !!doc.rollback && doc.rollback === curBuild;
    const hasRealFloor = high.manifest != null; // false: only the seed baseline has ever been seen

    if (high.seq != null && doc.seq < high.seq && !isRollback) return { status: "none" };

    if (hasRealFloor && doc.seq === high.seq) {
      // Same seq as what we already recorded: only a metadata resign (pause/resume/rollout) of
      // content we already staged/ran is legitimate; anything else is a seq collision, refused.
      if (doc.build !== high.build || doc.manifest !== high.manifest) return { status: "none" };
      const staged = this.staged();
      if (staged && staged.build === doc.build) return this._reconcileStaged(doc);
      return { status: "none" }; // already current, or nothing to do — never restage
    }

    const bad = readJson(this._badFile());
    if (bad && Array.isArray(bad.builds) && bad.builds.includes(doc.build)) return { status: "none" };

    // Refuse to restage into a tree that is (or was, and might still be running as) the active
    // one — finding 3. A genuine rollback is exempt for the `previous` case, since naming it is
    // the whole point; it is never exempt for `current` (rolling back to yourself is nonsensical).
    if (curBuild && doc.build === curBuild) {
      return { status: "refused", build: doc.build, reason: "build already applied to the running tree" };
    }
    if (previousBuild && doc.build === previousBuild && !isRollback) {
      return { status: "refused", build: doc.build, reason: "build matches the previous tree and is not a signed rollback" };
    }

    const already = this.staged();
    if (already && already.build === doc.build) {
      this._recordHighSeq(doc);
      return this._reconcileStaged(doc);
    }

    if (doc.paused) return { status: "paused", build: doc.build };
    if (!this._inRollout(doc)) return { status: "not-in-rollout", build: doc.build };
    if (this.shellVersion < doc.shell_min) {
      return { status: "needs-shell", build: doc.build, reason: `shell ${this.shellVersion} is older than the required ${doc.shell_min}` };
    }
    if (high.issued != null && typeof doc.issued === "string" && doc.issued < high.issued) {
      return { status: "refused", build: doc.build, reason: "issued is older than an already-seen pulse (freeze protection)" };
    }
    const head = await this.schemaHead();
    if (head != null && head > doc.schema_head) {
      return { status: "refused", build: doc.build, reason: `local schema ${head} is ahead of the payload's schema_head ${doc.schema_head}` };
    }

    await this._stageBuild(doc, rawPulse);
    this._recordHighSeq(doc);
    if (isRollback) this._addBad(doc.rollback, "rolled back");
    this.emit("staged", { build: doc.build, seq: doc.seq });
    return { status: "staged", build: doc.build };
  }

  /** A pulse re-signed for the build that is already staged: unstage it if the channel is now
   *  paused or rolled this install out of the bucket (finding 9 / stale staged.json), otherwise
   *  it is still good to activate. Never re-materialises — the tree on disk is untouched. */
  _reconcileStaged(doc) {
    if (doc.paused) { this._unstage(); return { status: "paused", build: doc.build }; }
    if (!this._inRollout(doc)) { this._unstage(); return { status: "not-in-rollout", build: doc.build }; }
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
    if (buf.length > MAX_MANIFEST_BYTES) throw new Error(`manifest exceeds the size cap (${MAX_MANIFEST_BYTES} bytes)`);
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

  async _stageBuild(doc, rawPulse) {
    const manifestBuf = await this._fetchVerified(this._manifestUrl(doc.manifest), doc.manifest);
    const manifest = JSON.parse(manifestBuf.toString("utf8"));
    if (manifest.build !== doc.build || manifest.platform !== this.platform) {
      throw new Error("the manifest does not match the pulse that named it");
    }
    validateManifest(manifest);
    await this._ensureSeedIndex();

    const need = [];
    const seen = new Set();
    for (const f of manifest.files) {
      if (seen.has(f.h)) continue;
      seen.add(f.h);
      const blobPath = this._blobPath(f.h);
      if (fs.existsSync(blobPath) && sha256Hex(fs.readFileSync(blobPath)) === f.h) continue; // verified good, reuse
      const seedRel = this._seedIndex && this._seedIndex.byHash.get(f.h);
      if (seedRel) {
        const seedBytes = fs.readFileSync(path.join(this.seedDir, ...seedRel.split("/")));
        if (sha256Hex(seedBytes) === f.h) { commitStoreFile(blobPath, seedBytes); continue; } // re-hashed before commit
      }
      need.push(f); // missing, or a stale/tampered store entry / seed-index entry — (re-)fetch
    }
    await pool(need, DOWNLOAD_CONCURRENCY, (f) => this._downloadBlob(f.h, f.s));

    this._materialise(doc.build, manifest, { pulseRaw: rawPulse, manifestRaw: manifestBuf });
    writeJsonAtomic(this._stagedFile(), { build: doc.build, seq: doc.seq, manifest: doc.manifest, schemaHead: doc.schema_head, shellMin: doc.shell_min });
  }

  /** Stream `h` to `<store>/<h>.partial`, resuming with Range if a previous attempt left bytes
   *  behind, then decompress and verify before it ever reaches the store. `s` is the manifest's
   *  declared decompressed size: it caps both the compressed download (s + 1 MiB) and the
   *  decompression itself (maxOutputLength), so a small malicious blob can never balloon into a
   *  multi-GB allocation (finding 2). A non-206 answer to a Range request (a stale or oversized
   *  `.partial`, e.g. 416) drops the partial and retries once with a plain GET (finding 8). */
  async _downloadBlob(h, s) {
    validateHash(h);
    const dest = this._blobPath(h);
    const part = `${dest}${PART_SUFFIX}`;
    ensureDir(path.dirname(part));
    let start = 0;
    try { start = fs.statSync(part).size; } catch { /* no partial yet */ }

    let res = await this._fetch(this._blobUrl(h), start > 0 ? { headers: { range: `bytes=${start}-` } } : {});
    if (start > 0 && res.status !== 206) {
      fs.rmSync(part, { force: true });
      start = 0;
      res = await this._fetch(this._blobUrl(h), {});
    }
    if (!res.ok) throw new Error(`blob host answered ${res.status} for ${h}`);
    const resumed = start > 0 && res.status === 206;
    if (!resumed) fs.rmSync(part, { force: true });
    const out = fs.createWriteStream(part, { flags: resumed ? "a" : "w" });
    const cap = Math.max(s + ONE_MIB - start, 0);
    try {
      await pipeline(res.body, sizeCap(cap, `blob ${h}`), out);
    } catch (err) {
      if (!out.closed) { out.destroy(); await new Promise((r) => out.once("close", r)); }
      if (err.isCapViolation) fs.rmSync(part, { force: true });
      throw err; // otherwise the partial file is left for the next check() to resume
    }

    const compressed = fs.readFileSync(part);
    let raw;
    try {
      raw = brotliDecompressSync(compressed, { maxOutputLength: s });
    } catch (err) {
      fs.rmSync(part, { force: true });
      throw new Error(`blob ${h} does not decompress (${err.message})`);
    }
    if (raw.length !== s) {
      fs.rmSync(part, { force: true });
      throw new Error(`blob ${h} decompressed to the wrong size (tampered)`);
    }
    if (sha256Hex(raw) !== h) {
      fs.rmSync(part, { force: true });
      throw new Error(`blob ${h} does not match its hash (tampered)`);
    }
    commitStoreFile(dest, raw);
    fs.rmSync(part, { force: true });
  }

  /** If `blobPath` needs to be executable, chmod the STORE blob itself (never a tree's hardlink
   *  to it, which would silently reach back into the store — the same inode). Safe to call
   *  repeatedly; a no-op once the bit is already set. */
  _ensureExecutable(blobPath) {
    try {
      const st = fs.statSync(blobPath);
      if ((st.mode & 0o111) === 0) fs.chmodSync(blobPath, 0o555);
    } catch { /* the blob was just committed by this same call; should not happen */ }
  }

  /** Hardlink (copy fallback) every manifest file from the store into a fresh
   *  `versions/<build>.tmp-<rand>/`, write `.pulse.json`/`.manifest.raw`/`.complete`, fsync, then
   *  rename onto `versions/<build>/`. Never rewrites an existing, complete version dir — the
   *  caller (check()) is also responsible for never calling this for the running build (finding 3). */
  _materialise(build, manifest, raws) {
    const dir = this._versionDir(build);
    if (fs.existsSync(path.join(dir, ".complete"))) return;
    const tmpDir = `${dir}.tmp-${randomBytes(6).toString("hex")}`;
    fs.rmSync(tmpDir, { recursive: true, force: true });
    for (const f of manifest.files) {
      const dest = path.join(tmpDir, ...f.p.split("/"));
      ensureDir(path.dirname(dest));
      const blobPath = this._blobPath(f.h);
      if (f.x) this._ensureExecutable(blobPath);
      linkOrCopy(blobPath, dest);
    }
    fs.writeFileSync(path.join(tmpDir, ".pulse.json"), raws.pulseRaw);
    fs.writeFileSync(path.join(tmpDir, ".manifest.raw"), raws.manifestRaw);
    const marker = path.join(tmpDir, ".complete");
    fs.writeFileSync(marker, "");
    fsyncFile(marker);
    fsyncDir(tmpDir);
    fs.renameSync(tmpDir, dir);
    fsyncDir(path.dirname(dir));
  }

  /** The verified, materialised build waiting to be activated, or null. */
  staged() {
    const s = readJson(this._stagedFile());
    if (!s) return null;
    const dir = this._versionDir(s.build);
    if (!fs.existsSync(path.join(dir, ".complete"))) return null;
    return { build: s.build, seq: s.seq, dir, schemaHead: s.schemaHead, shellMin: s.shellMin };
  }

  /** Switch current.json to the staged build as a trial. Re-checks the staged build is still
   *  safe to apply (bad-list, shell_min, schemaHead — finding 9): time may have passed since
   *  check() staged it. A staged build that already equals current (a crash between
   *  writing current.json and clearing staged.json) is cleaned up idempotently instead of
   *  corrupting `previous` into equalling `current`. */
  async activate() {
    const s = this.staged();
    if (!s) throw new Error("nothing staged to activate");
    const current = readJson(this._currentFile());
    const curBuild = current && current.build ? current.build : null;

    if (s.build === curBuild) {
      this._unstage();
      return { dir: s.dir, build: curBuild, previous: current.previous ? current.previous.build : null };
    }
    // Not a numeric high_seq re-check: a legitimately staged rollback always has seq below the
    // floor by design (that is the point of a rollback), so bad.json — which every mechanism
    // that invalidates a staged build (revert(), rollback acceptance) writes to — is the correct
    // and only re-check for "has this staged build been invalidated since it was staged".
    const bad = readJson(this._badFile());
    if (bad && Array.isArray(bad.builds) && bad.builds.includes(s.build)) {
      this._unstage();
      throw new Error(`staged build ${s.build} is now marked bad`);
    }
    if (this.shellVersion < s.shellMin) {
      throw new Error(`shell ${this.shellVersion} is older than the staged build's required ${s.shellMin}`);
    }
    const head = await this.schemaHead();
    if (head != null && s.schemaHead != null && head > s.schemaHead) {
      throw new Error(`local schema ${head} is ahead of the staged build's schema_head ${s.schemaHead}`);
    }

    const prev = this._currentOrStub();
    const previous = curBuild
      ? { build: current.build, seq: current.seq }
      : this.seedBuild ? { build: this.seedBuild, seq: this.seedSeq } : null;
    writeJsonAtomic(this._currentFile(), {
      build: s.build, seq: s.seq, previous, trial: true, trial_started: Date.now(), boots: 0, failures: [],
      high_seq: prev.high_seq, high_seq_build: prev.high_seq_build,
      high_seq_manifest: prev.high_seq_manifest, high_seq_issued: prev.high_seq_issued,
    });
    this._unstage();
    return { dir: s.dir, build: s.build, previous: previous ? previous.build : null };
  }

  /** Trial -> confirmed. Runs GC (§3.3 step 7). */
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

  /** Immediate revert to previous; the reverted-from build is marked bad (never re-applied).
   *  Preserves the high_seq floor — a revert must never lower the replay-protection floor
   *  alongside `seq` (finding 5). */
  revert(reason) {
    const current = readJson(this._currentFile());
    if (!current || !current.previous) throw new Error("no previous build to revert to");
    this._addBad(current.build, reason);

    const { previous } = current;
    writeJsonAtomic(this._currentFile(), {
      build: previous.build, seq: previous.seq, previous: null, trial: false, trial_started: null, boots: 0, failures: [],
      high_seq: current.high_seq, high_seq_build: current.high_seq_build,
      high_seq_manifest: current.high_seq_manifest, high_seq_issued: current.high_seq_issued,
    });
    const dir = this._versionDir(previous.build);
    return { dir: fs.existsSync(path.join(dir, ".complete")) ? dir : this.seedDir, build: previous.build };
  }

  /** Re-verifies the active build's `.pulse.json`/`.manifest.raw` (never a re-serialised copy —
   *  finding 4), then re-hashes `relPaths` against that manifest; throws on any mismatch. */
  verifyEntry(relPaths) {
    const current = readJson(this._currentFile());
    if (!current || !current.build) throw new Error("nothing active to verify");
    const dir = this._versionDir(current.build);
    const loaded = this._loadVerifiedTree(dir);
    if (!loaded) throw new Error(`no verified manifest for ${current.build}`);
    const byPath = new Map(loaded.manifest.files.map((f) => [f.p, f]));
    for (const rel of relPaths) {
      const entry = byPath.get(rel);
      if (!entry) throw new Error(`${rel} is not part of the ${current.build} manifest`);
      const actual = sha256Hex(fs.readFileSync(path.join(dir, ...rel.split("/"))));
      if (actual !== entry.h) throw new Error(`${rel} does not match the manifest (tampered)`);
    }
  }

  /** Keeps exactly the version trees named by current.json ({current, previous}) and
   *  staged.json ({staged}) — never by mtime (finding 1) — drops every other version dir
   *  (including any stray `.tmp-*` materialise directory left by a crash), sweeps store blobs no
   *  kept tree's manifest references, and sweeps `.partial` files older than a day. Not in the
   *  frozen §3.10 table — GC has no listed entry point there — but §3.3 requires the behaviour,
   *  so it also runs automatically from confirm(). */
  gc() {
    const versionsDir = path.join(this.root, "versions");
    const current = readJson(this._currentFile());
    const staged = readJson(this._stagedFile());
    const keep = new Set();
    if (current && current.build) keep.add(current.build);
    if (current && current.previous) keep.add(current.previous.build);
    if (staged && staged.build) keep.add(staged.build);

    let names;
    try { names = fs.readdirSync(versionsDir); } catch { names = []; }
    const referenced = new Set();
    for (const n of names) {
      const full = path.join(versionsDir, n);
      if (n.includes(".tmp-") || !keep.has(n)) { fs.rmSync(full, { recursive: true, force: true }); continue; }
      try {
        const manifest = JSON.parse(fs.readFileSync(path.join(full, ".manifest.raw"), "utf8"));
        for (const f of manifest.files) referenced.add(f.h);
      } catch { /* incomplete/corrupt tree: nothing of its to keep referenced */ }
    }

    let prefixes;
    try { prefixes = fs.readdirSync(path.join(this.root, "store")); } catch { prefixes = []; }
    const now = Date.now();
    for (const prefix of prefixes) {
      const pdir = path.join(this.root, "store", prefix);
      let blobs;
      try { blobs = fs.readdirSync(pdir); } catch { continue; }
      for (const h of blobs) {
        const full = path.join(pdir, h);
        if (h.endsWith(PART_SUFFIX)) {
          let st;
          try { st = fs.statSync(full); } catch { continue; }
          if (now - st.mtimeMs > ONE_DAY_MS) fs.rmSync(full, { force: true });
          continue;
        }
        if (!referenced.has(h)) fs.rmSync(full, { force: true });
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

module.exports = { createPayloadClient, hashTree, validateBuild, validateHash, validateRelPath, validateManifest, PULSE_DOMAIN };
