#!/usr/bin/env node
// publish-payload.mjs [publish] --app --channel --platform --build --seq --schema-head --shell-min
//   --tree <dir> --out <staging dir> --key-env <ENV VAR> --key-id <id> [--have <file of blob
//   hashes on the server>] [--rollout N] [--paused] [--rollback <build>]
//
// Walks --tree (hashTree, shared with the client's seed mapping), brotli(q9)-compresses every
// blob not listed in --have, writes the p/ layout (new blobs, manifest, pulse — bytes before
// pointer, same ordering as the rest of the release path) under --out, and signs the pulse with
// signed-feed.js (same envelope/domain the client verifies, no unsigned fallback). Refuses to
// write a pulse whose seq is <= one already staged in --out for this app/channel/platform.
//
// --key-env names an env var holding the raw ed25519 PKCS8 PEM, newlines optionally encoded as
// `|` (the format of MASORA_UPDATE_SIGNING_KEY / ZEVET_UPDATE_SIGNING_KEY); --key-id is its pinned id.
//
// Ops subcommands re-sign a pulse in --out (a local mirror of the server's p/ tree) with no
// rebuild. Blobs and manifests are never touched; a manifest that is not already in --out/p/m is
// an error, not something to repair. All take --app --platform --out --key-env --key-id, plus:
//   promote  --from canary --to stable [--rollout N]
//   pause | resume  --channel
//   rollback --channel --to <build> [--manifest <sha256>] [--schema-head N] [--shell-min N]
//
// seq rule — a pulse that changes the build gets a seq strictly above the channel's current one:
//   publish   the given --seq (must exceed the staged one)
//   promote   max(stable seq + 1, canary seq): equals the canary seq in the normal case, and
//             still moves forward when stable has already passed it
//   rollback  current seq + 1, with `rollback` naming the build being left
// pause/resume re-sign the SAME seq (only `paused` and `issued` change): a higher seq on the same
// build would make every client re-stage the build it is already running.
import { createHash, createPrivateKey } from "node:crypto";
import { brotliCompressSync, constants as zlibConstants } from "node:zlib";
import fs from "node:fs";
import path from "node:path";
import { hashTree, validateBuild, validateManifest, PULSE_DOMAIN } from "../lib/payload.js";
import { signDocument } from "../lib/signed-feed.js";

function fail(msg) {
  console.error(msg);
  process.exit(1);
}

function parseArgs(argv) {
  const out = {};
  for (let i = 0; i < argv.length; i++) {
    if (!argv[i].startsWith("--")) continue;
    const name = argv[i].slice(2);
    if (name === "paused") { out.paused = true; continue; }
    out[name] = argv[++i];
  }
  return out;
}

function need(args, names) {
  for (const req of names) if (args[req] === undefined) fail(`--${req} is required`);
}

const int = (v, name) => {
  const n = Number(v);
  if (!Number.isInteger(n)) fail(`--${name} must be an integer`);
  return n;
};

function loadKey(args) {
  const raw = process.env[args["key-env"]];
  if (!raw) fail(`env var ${args["key-env"]} is not set`);
  const pem = raw.replaceAll("|", "\n").trim();
  try {
    createPrivateKey(pem);
  } catch {
    fail(`${args["key-env"]} is not a PEM private key (raw PKCS8, newlines may be encoded as "|")`);
  }
  return { pem, keyId: args["key-id"] };
}

const pulsePathOf = (out, app, channel, platform) => path.join(out, "p", app, channel, platform, "pulse.json");

/** The signed document of the pulse staged in --out, or fail. */
function readPulse(out, app, channel, platform) {
  const file = pulsePathOf(out, app, channel, platform);
  if (!fs.existsSync(file)) fail(`no pulse at ${file}`);
  const doc = JSON.parse(fs.readFileSync(file, "utf8"))?.signed;
  if (!doc || !Number.isInteger(doc.seq)) fail(`${file} has no signed pulse with an integer seq`);
  return doc;
}

function requireManifest(out, hash) {
  if (!fs.existsSync(path.join(out, "p", "m", `${hash}.json`))) fail(`manifest ${hash} is not in ${path.join(out, "p", "m")}`);
}

/** Sign `doc` and write it as the channel's pulse. */
function writePulse(out, doc, key) {
  const file = pulsePathOf(out, doc.app, doc.channel, doc.platform);
  const body = { signed: doc, signature: signDocument(PULSE_DOMAIN, doc, key.pem, key.keyId) };
  fs.mkdirSync(path.dirname(file), { recursive: true });
  const tmp = `${file}.tmp`;
  fs.writeFileSync(tmp, JSON.stringify(body));
  fs.renameSync(tmp, file);
}

const resign = (cur, changes) => ({ ...cur, ...changes, issued: new Date().toISOString() });

function promote(args) {
  need(args, ["app", "platform", "from", "to", "out", "key-env", "key-id"]);
  const { app, platform, from, to } = args;
  const out = path.resolve(args.out);
  if (from === to) fail("--from and --to must differ");
  const src = readPulse(out, app, from, platform);
  requireManifest(out, src.manifest);
  const stablePath = pulsePathOf(out, app, to, platform);
  const dst = fs.existsSync(stablePath) ? readPulse(out, app, to, platform) : null;
  if (dst && dst.manifest === src.manifest && dst.build === src.build) fail(`${to} already carries ${src.build}`);
  const key = loadKey(args);
  const doc = {
    app, channel: to, platform, build: src.build,
    seq: Math.max((dst ? dst.seq : 0) + 1, src.seq),
    manifest: src.manifest, shell_min: src.shell_min, schema_head: src.schema_head,
    rollout: args.rollout !== undefined ? int(args.rollout, "rollout") : 100,
    paused: false, issued: new Date().toISOString(),
  };
  writePulse(out, doc, key);
  console.log(`promoted ${app}/${platform} ${src.build}: ${from} seq ${src.seq} -> ${to} seq ${doc.seq}`);
}

function setPaused(args, paused) {
  need(args, ["app", "channel", "platform", "out", "key-env", "key-id"]);
  const out = path.resolve(args.out);
  const cur = readPulse(out, args.app, args.channel, args.platform);
  if (!!cur.paused === paused) fail(`${args.app}/${args.channel}/${args.platform} is already ${paused ? "paused" : "running"}`);
  writePulse(out, resign(cur, { paused }), loadKey(args));
  console.log(`${paused ? "paused" : "resumed"} ${args.app}/${args.channel}/${args.platform} at seq ${cur.seq}`);
}

function findManifest(out, build, platform) {
  const dir = path.join(out, "p", "m");
  const hits = fs.existsSync(dir)
    ? fs.readdirSync(dir).filter((f) => f.endsWith(".json")).filter((f) => {
        const m = JSON.parse(fs.readFileSync(path.join(dir, f), "utf8"));
        return m.build === build && m.platform === platform;
      }).map((f) => f.slice(0, -5))
    : [];
  if (hits.length !== 1) fail(`${hits.length} manifests for build ${build} in ${dir}; ${hits.length ? "pass --manifest <sha256> to pick one" : "pull it from the server or pass --manifest"}`);
  return hits[0];
}

function rollback(args) {
  need(args, ["app", "channel", "platform", "to", "out", "key-env", "key-id"]);
  const { app, channel, platform, to } = args;
  try { validateBuild(to); } catch (err) { fail(err.message); }
  const out = path.resolve(args.out);
  const cur = readPulse(out, app, channel, platform);
  if (cur.build === to) fail(`${channel} is already on ${to}`);
  const manifest = args.manifest ?? findManifest(out, to, platform);
  requireManifest(out, manifest);
  const doc = resign(cur, {
    build: to, seq: cur.seq + 1, manifest, rollback: cur.build,
    ...(args["schema-head"] !== undefined ? { schema_head: int(args["schema-head"], "schema-head") } : {}),
    ...(args["shell-min"] !== undefined ? { shell_min: int(args["shell-min"], "shell-min") } : {}),
  });
  writePulse(out, doc, loadKey(args));
  console.log(`rolled back ${app}/${channel}/${platform}: ${cur.build} -> ${to} at seq ${doc.seq}`);
}

async function publish(args) {
  need(args, ["app", "channel", "platform", "build", "seq", "schema-head", "shell-min", "tree", "out", "key-env", "key-id"]);
  const { app, channel, platform, build } = args;
  const seq = int(args.seq, "seq");
  const schemaHead = int(args["schema-head"], "schema-head");
  const shellMin = int(args["shell-min"], "shell-min");
  const tree = path.resolve(args.tree);
  const out = path.resolve(args.out);
  const rollout = args.rollout !== undefined ? int(args.rollout, "rollout") : 100;
  const key = loadKey(args);

  try { validateBuild(build); } catch (err) { fail(err.message); }

  const have = new Set();
  if (args.have) {
    for (const line of fs.readFileSync(path.resolve(args.have), "utf8").split(/\r?\n/)) {
      const h = line.trim();
      if (!h) continue;
      if (!/^[0-9a-f]{64}$/.test(h)) fail(`--have contains an invalid hash: ${JSON.stringify(h)}`);
      have.add(h);
    }
  }

  const pulsePath = pulsePathOf(out, app, channel, platform);
  if (fs.existsSync(pulsePath)) {
    const existingSeq = JSON.parse(fs.readFileSync(pulsePath, "utf8"))?.signed?.seq;
    if (Number.isInteger(existingSeq) && seq <= existingSeq) {
      fail(`refusing to publish seq ${seq}: ${pulsePath} already has seq ${existingSeq}`);
    }
  }

  const files = await hashTree(tree);
  const written = new Set();
  for (const f of files) {
    if (have.has(f.h) || written.has(f.h)) continue;
    written.add(f.h);
    const dest = path.join(out, "p", "b", f.h.slice(0, 2), f.h);
    if (fs.existsSync(dest)) continue;
    fs.mkdirSync(path.dirname(dest), { recursive: true });
    const raw = fs.readFileSync(path.join(tree, ...f.p.split("/")));
    const compressed = brotliCompressSync(raw, { params: { [zlibConstants.BROTLI_PARAM_QUALITY]: 9 } });
    const tmp = `${dest}.tmp`;
    fs.writeFileSync(tmp, compressed);
    fs.renameSync(tmp, dest);
  }

  const entryFile = path.join(tree, "entry.json");
  const entry = fs.existsSync(entryFile) ? JSON.parse(fs.readFileSync(entryFile, "utf8")) : {};

  const manifest = { build, platform, files: files.map(({ p, h, s, x }) => ({ p, h, s, x })), entry };
  try { validateManifest(manifest); } catch (err) { fail(err.message); }
  const manifestBytes = Buffer.from(JSON.stringify(manifest));
  const manifestHash = createHash("sha256").update(manifestBytes).digest("hex");
  const manifestPath = path.join(out, "p", "m", `${manifestHash}.json`);
  fs.mkdirSync(path.dirname(manifestPath), { recursive: true });
  const manifestTmp = `${manifestPath}.tmp`;
  fs.writeFileSync(manifestTmp, manifestBytes);
  fs.renameSync(manifestTmp, manifestPath);

  writePulse(out, {
    app, channel, platform, build, seq,
    manifest: manifestHash,
    shell_min: shellMin,
    schema_head: schemaHead,
    rollout,
    paused: !!args.paused,
    issued: new Date().toISOString(),
    ...(args.rollback ? { rollback: args.rollback } : {}),
  }, key);

  console.log(`published ${app}/${channel}/${platform} build ${build} seq ${seq}: ${written.size} new blob(s), manifest ${manifestHash}`);
}

const argv = process.argv.slice(2);
const sub = argv[0] && !argv[0].startsWith("--") ? argv.shift() : "publish";
const args = parseArgs(argv);
const commands = { publish, promote, pause: (a) => setPaused(a, true), resume: (a) => setPaused(a, false), rollback };
if (!commands[sub]) fail(`unknown subcommand ${sub} (publish|promote|pause|resume|rollback)`);
Promise.resolve(commands[sub](args)).catch((err) => fail(err.stack || err.message));
