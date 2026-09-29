"use strict";
// Updater core: check -> download -> verify sha -> ready -> install (now / on quit).
// Everything platform- or app-specific is injected; the trust model is fixed:
//
//  1. The feed is Ed25519-signed (signed-feed.js). version / file / sha256 / size
//     are read ONLY from the signed document; unsigned legacy top-level fields
//     are ignored. No fallback.
//  2. The sha256 binds the signed feed to the exact installer bytes; the stream
//     is size-capped and written to `.part`, renamed only once it verifies.
//  3. The manifest names a FILE, resolved beside the feed itself — never a host.
//  4. `steps.publisherProblem(file)` (optional, async) may veto an installer.
//  5. A downloaded file is re-verified at the moment of install, not trusted
//     from when the download finished.
//
// Injected (`opts`): domain, trustedKeys, feedUrl, currentVersion, dir,
//   artifactName(version, platformKey) -> the one file name allowed (or null = any safe name),
//   steps: { restart(updater), onQuit(updater), publisherProblem(file) }.
const fs = require("node:fs");
const path = require("node:path");
const { createHash } = require("node:crypto");
const { pipeline } = require("node:stream/promises");
const { verifyFeed } = require("./signed-feed.js");

const MAX_BYTES = 400 * 1024 * 1024;
const MANIFEST_TIMEOUT_MS = 12000;
const DOWNLOAD_TIMEOUT_MS = 10 * 60 * 1000;
const FIRST_CHECK_MS = 25 * 1000;
const EVERY_MS = 60 * 60 * 1000;

/** Numeric dotted compare — not string compare ("0.10.0" > "0.9.0"). Pre-release
 *  suffixes are unsupported: `-rc1` sorts as the release. */
function compareVersions(a, b) {
  const pa = String(a || "").split(".").map((n) => parseInt(n, 10) || 0);
  const pb = String(b || "").split(".").map((n) => parseInt(n, 10) || 0);
  for (let i = 0; i < Math.max(pa.length, pb.length); i++) {
    const x = pa[i] || 0;
    const y = pb[i] || 0;
    if (x !== y) return x < y ? -1 : 1;
  }
  return 0;
}

const platformKey = (platform, arch) => `${platform}-${arch}`;

/** A file name that is safe to write and run: `path.join` treats `../` as an instruction. */
function safeArtifactName(name, exts = /\.(exe|dmg)$/i) {
  return typeof name === "string" && name.length > 0 && name.length <= 128 &&
    /^[A-Za-z0-9][A-Za-z0-9._-]*$/.test(name) && !name.includes("..") && exts.test(name);
}

/** Where an artifact may be fetched from: beside the feed (same origin AND directory), or null. */
function artifactUrl(feedUrl, file, exts) {
  if (!safeArtifactName(file, exts)) return null;
  let base;
  try {
    base = new URL(feedUrl);
  } catch {
    return null;
  }
  const url = new URL(file, base);
  if (url.origin !== base.origin) return null;
  const dir = base.pathname.slice(0, base.pathname.lastIndexOf("/") + 1);
  if (url.pathname !== dir + file) return null;
  return url;
}

/** Is this signed document a manifest, and does it describe THIS machine?
 *  `{ error }` or `{ version, notes, entry }`; validated whole, never partly obeyed. */
function readManifest(json, key, { artifactName, maxBytes = MAX_BYTES, exts } = {}) {
  if (!json || typeof json !== "object") return { error: "the feed is not an object" };
  if (typeof json.version !== "string" || !/^\d+(\.\d+){0,3}$/.test(json.version)) {
    return { error: `the feed has no usable version (${JSON.stringify(json.version)})` };
  }
  const platforms = json.platforms;
  if (!platforms || typeof platforms !== "object") return { error: "the feed lists no platforms" };
  const entry = platforms[key];
  if (!entry) return { error: `the feed has no build for ${key}` };
  if (!safeArtifactName(entry.file, exts)) return { error: `refusing the file name ${JSON.stringify(entry.file)}` };
  if (artifactName) {
    const want = artifactName(json.version, key);
    if (!want || entry.file !== want) return { error: `${entry.file} is not the ${key} artifact for version ${json.version}` };
  }
  if (typeof entry.sha256 !== "string" || !/^[0-9a-f]{64}$/.test(entry.sha256)) return { error: `${entry.file} has no usable sha256` };
  if (!Number.isInteger(entry.bytes) || entry.bytes <= 0 || entry.bytes > maxBytes) return { error: `${entry.file} has no usable size` };
  return {
    version: json.version,
    notes: typeof json.notes === "string" ? json.notes.slice(0, 2000) : "",
    entry: { file: entry.file, sha256: entry.sha256.toLowerCase(), bytes: entry.bytes },
  };
}

class UpdaterCore {
  constructor(o = {}) {
    if (!o.feedUrl) throw new Error("UpdaterCore: feedUrl is required");
    if (typeof o.domain !== "string" && !Buffer.isBuffer(o.domain)) throw new Error("UpdaterCore: domain is required");
    if (!o.trustedKeys) throw new Error("UpdaterCore: trustedKeys is required");
    this.currentVersion = String(o.currentVersion || "0.0.0");
    this.feedUrl = String(o.feedUrl);
    this.domain = o.domain;
    this.trustedKeys = o.trustedKeys;
    this.feedField = o.feedField; // "signed" | "payload" | undefined = either
    this.platform = o.platform || process.platform;
    this.key = o.platformKey || platformKey(this.platform, process.arch);
    this.dir = o.dir;
    this.fetchImpl = o.fetchImpl || ((...a) => fetch(...a));
    this.downloadTimeoutMs = o.downloadTimeoutMs || DOWNLOAD_TIMEOUT_MS;
    this.artifactName = o.artifactName;
    this.exts = o.exts;
    this.maxBytes = o.maxBytes || MAX_BYTES;
    this.steps = o.steps || {};
    this.onStatus = typeof o.onStatus === "function" ? o.onStatus : () => {};
    this.log = typeof o.log === "function" ? o.log : () => {};

    /** Everything the renderer is told, and the only state that leaves here. */
    this.state = { phase: "idle", version: null, notes: "", file: null, percent: 0, error: null, canInstall: false, ...o.state };
    this._timer = null;
    this._busy = false;
    this._readyEntry = null;
    this._lastCheckAt = 0;
  }

  status() {
    return Object.assign({ current: this.currentVersion }, this.state);
  }

  _set(patch) {
    Object.assign(this.state, patch);
    try {
      this.onStatus(this.status());
    } catch {
      // A status listener that throws must not take the updater with it.
    }
  }

  /** Begin checking (first after FIRST_CHECK_MS, then hourly). A second call is ignored. */
  start() {
    if (this._timer) return;
    this._timer = setTimeout(() => {
      this._timer = setInterval(() => this.check(), EVERY_MS);
      if (this._timer.unref) this._timer.unref();
      this.check();
    }, FIRST_CHECK_MS);
    if (this._timer.unref) this._timer.unref();
  }

  stop() {
    if (!this._timer) return;
    clearTimeout(this._timer);
    clearInterval(this._timer);
    this._timer = null;
  }

  /** A check gated by how recently one last ran (focus / wake-from-sleep). */
  async maybeCheck(minGapMs) {
    if (Date.now() - this._lastCheckAt < minGapMs) return this.status();
    return this.check();
  }

  /** Look for a newer build and, if there is one, fetch and verify it. Never installs. */
  async check() {
    if (this._busy) return this.status();
    this._busy = true;
    this._lastCheckAt = Date.now();
    try {
      this._readyEntry = null;
      this._set({ phase: "checking", error: null, file: null, canInstall: false });
      const ac = new AbortController();
      const timer = setTimeout(() => ac.abort(), MANIFEST_TIMEOUT_MS);
      let json;
      try {
        // A redirect is never legitimate for a feed: following one is how a request lands somewhere unintended.
        const res = await this.fetchImpl(this.feedUrl, { signal: ac.signal, redirect: "error", headers: { accept: "application/json" } });
        if (!res.ok) {
          // 404 is the ordinary state of a host that has not published a feed yet.
          this._set({ phase: res.status === 404 ? "current" : "error", error: res.status === 404 ? null : `the download host answered ${res.status}` });
          return this.status();
        }
        json = await res.json();
      } finally {
        clearTimeout(timer);
      }

      let doc;
      try {
        doc = verifyFeed(json, this.domain, this.trustedKeys, this.feedField);
      } catch (err) {
        const error = `the feed is not validly signed: ${err.message}`;
        this.log(`rejecting the update feed: ${error}`);
        this._set({ phase: "error", error });
        return this.status();
      }
      const m = readManifest(doc, this.key, { artifactName: this.artifactName, maxBytes: this.maxBytes, exts: this.exts });
      if (m.error) {
        this.log(`rejecting the update feed: ${m.error}`);
        this._set({ phase: "error", error: m.error });
        return this.status();
      }
      if (compareVersions(m.version, this.currentVersion) <= 0) {
        // Right after a successful install and relaunch: nothing in `dir` is still needed.
        this._pruneOldInstallers([]);
        this._set({ phase: "current", version: null, error: null, canInstall: false });
        return this.status();
      }

      const url = artifactUrl(this.feedUrl, m.entry.file, this.exts);
      if (!url) {
        this._set({ phase: "error", error: `refusing to fetch ${m.entry.file} from this feed` });
        return this.status();
      }

      // Already downloaded and verified on a previous run? Say ready without re-downloading.
      const dest = path.join(this.dir, m.entry.file);
      if (this._verified(dest, m.entry)) {
        const bad = await this._publisherProblem(dest);
        if (bad) return this._rejectInstaller(dest, bad);
        this._readyEntry = m.entry;
        this._pruneOldInstallers([m.entry.file]);
        this._set({ phase: "ready", version: m.version, notes: m.notes, file: dest, percent: 100, canInstall: true, error: null });
        return this.status();
      }

      this._set({ phase: "downloading", version: m.version, notes: m.notes, percent: 0, canInstall: false });
      await this._download(url, dest, m.entry);
      const bad = await this._publisherProblem(dest);
      if (bad) return this._rejectInstaller(dest, bad);
      this._readyEntry = m.entry;
      this._pruneOldInstallers([m.entry.file]);
      this._set({ phase: "ready", file: dest, percent: 100, canInstall: true });
      this.log(`${this.currentVersion} -> ${m.version} downloaded and verified`);
      return this.status();
    } catch (err) {
      this.log(`update check failed: ${err && err.message}`);
      this._set({ phase: "error", error: (err && err.message) || "the check failed" });
      return this.status();
    } finally {
      this._busy = false;
    }
  }

  /** A message when the installer must be refused, null otherwise (or when no check is wired). */
  async _publisherProblem(file) {
    return this.steps.publisherProblem ? this.steps.publisherProblem(file) : null;
  }

  _rejectInstaller(file, why) {
    this.log(`rejecting the download: ${why}`);
    try { fs.rmSync(file, { force: true }); } catch { /* the next prune gets it */ }
    this._set({ phase: "error", error: why, file: null, canInstall: false });
    return this.status();
  }

  /** `dir` otherwise only grows. `keep` is file names, not paths; deletion is
   *  best-effort (a file mid-install is locked by the OS). The install-on-quit
   *  marker is never a stale installer. */
  _pruneOldInstallers(keep) {
    let names;
    try {
      names = fs.readdirSync(this.dir);
    } catch {
      return; // no directory yet
    }
    const keeping = new Set(["install-on-quit.json", ...keep]);
    for (const name of names) {
      if (keeping.has(name)) continue;
      try {
        fs.rmSync(path.join(this.dir, name), { force: true });
      } catch {
        // locked or already gone — leave it for the next prune
      }
    }
  }

  /** Is `file` on disk exactly the artifact the manifest describes? */
  _verified(file, entry) {
    try {
      const st = fs.statSync(file);
      if (!st.isFile() || st.size !== entry.bytes) return false;
      return createHash("sha256").update(fs.readFileSync(file)).digest("hex") === entry.sha256;
    } catch {
      return false;
    }
  }

  /** Stream to `.part`, verify size and sha, and only then give it its real name:
   *  an installer at its final path is one a later run will execute. */
  async _download(url, dest, entry) {
    fs.mkdirSync(this.dir, { recursive: true });
    const part = dest + ".part";
    fs.rmSync(part, { force: true });
    const ac = new AbortController();
    const timer = setTimeout(() => ac.abort(), this.downloadTimeoutMs);
    try {
      const res = await this.fetchImpl(url.href, { redirect: "error", signal: ac.signal });
      if (!res.ok) throw new Error(`the download host answered ${res.status} for ${entry.file}`);

      const hash = createHash("sha256");
      let got = 0;
      const checkChunk = (buf) => {
        got += buf.length;
        if (got > entry.bytes) throw new Error("the download is longer than the manifest says");
        hash.update(buf);
        const pct = Math.floor((got / entry.bytes) * 100);
        if (pct !== this.state.percent) this._set({ percent: pct });
      };
      // pipeline observes writer errors from the start, handles backpressure, and closes before cleanup.
      await pipeline(res.body, async function* (source) {
        for await (const chunk of source) {
          const buf = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk);
          checkChunk(buf);
          yield buf;
        }
      }, fs.createWriteStream(part), { signal: ac.signal });

      if (got !== entry.bytes) throw new Error(`the download is ${got} bytes and the manifest says ${entry.bytes}`);
      if (hash.digest("hex") !== entry.sha256) throw new Error("the download does not match the checksum the feed published");
      fs.renameSync(part, dest);
    } catch (err) {
      try { fs.rmSync(part, { force: true }); } catch { /* the next run overwrites it */ }
      throw err;
    } finally {
      clearTimeout(timer);
    }
  }

  /** Put the downloaded build on, now. Called from a button, never a timer. */
  async install() {
    const v = this._verifyReady();
    if (!v.ok) return v;
    if (!this.steps.restart) return { ok: false, error: `${this.platform} builds are not published` };
    return this.steps.restart(this);
  }

  /** Apply a verified build with NO relaunch, once, as the app quits. A marker is
   *  written BEFORE the attempt: a quitting process cannot observe whether the
   *  installer it spawned failed, so that still counts as the one try, and a failed
   *  silent install falls back to the in-app bar instead of retrying at every quit. */
  installOnQuit() {
    const v = this._verifyReady();
    if (!v.ok) return v;
    if (!this.steps.onQuit) return { ok: false, error: `${this.platform} builds cannot install silently on quit` };

    const marker = path.join(this.dir, "install-on-quit.json");
    let already = null;
    try {
      already = JSON.parse(fs.readFileSync(marker, "utf8"));
    } catch {
      // No marker yet, or unreadable — nothing tried.
    }
    if (already && already.version === this.state.version) {
      return { ok: false, error: "already attempted this version once; leaving it for the in-app bar" };
    }
    try {
      fs.mkdirSync(this.dir, { recursive: true });
      fs.writeFileSync(marker, JSON.stringify({ version: this.state.version }));
    } catch {
      // Best-effort: proceed even if the marker itself could not be written.
    }
    return this.steps.onQuit(this);
  }

  /** Is there a downloaded file that still exists and still matches the entry that made it "ready"? */
  _verifyReady() {
    if (this.state.phase !== "ready" || !this.state.file) return { ok: false, error: "there is nothing downloaded to install" };
    if (!this._exists(this.state.file)) {
      this._set({ phase: "idle", canInstall: false, file: null });
      return { ok: false, error: "the downloaded file is gone; it will be fetched again" };
    }
    if (!this._readyEntry || !this._verified(this.state.file, this._readyEntry)) {
      this._readyEntry = null;
      const error = "the downloaded file changed; check for updates to fetch it again";
      this._set({ phase: "error", canInstall: false, file: null, error });
      return { ok: false, error };
    }
    return { ok: true };
  }

  _exists(f) {
    try {
      return fs.statSync(f).isFile();
    } catch {
      return false;
    }
  }
}

module.exports = { UpdaterCore, compareVersions, platformKey, safeArtifactName, artifactUrl, readManifest, MAX_BYTES, EVERY_MS };
