#!/usr/bin/env node
// publish-payload.mjs --app --channel --platform --build --seq --schema-head --shell-min
//   --tree <dir> --out <staging dir> --key-env <ENV VAR> [--have <file of blob hashes on the
//   server>] [--rollout N] [--paused] [--rollback <build>]
//
// Walks --tree (hashTree, shared with the client's seed mapping), brotli(q9)-compresses every
// blob not listed in --have, writes the p/ layout (new blobs, manifest, pulse — bytes before
// pointer, same ordering as the rest of the release path) under --out, and signs the pulse with
// signed-feed.js (same envelope/domain the client verifies, no unsigned fallback). Refuses to
// write a pulse whose seq is <= one already staged in --out for this app/channel/platform.
//
// --key-env names an env var holding JSON {"key_id": "...", "private_key": "<ed25519 PEM>"}:
// §3.10 does not say how the signing key id reaches the publisher, so this is that choice.
import { createHash } from "node:crypto";
import { brotliCompressSync, constants as zlibConstants } from "node:zlib";
import fs from "node:fs";
import path from "node:path";
import { hashTree, PULSE_DOMAIN } from "../lib/payload.js";
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

async function main() {
  const args = parseArgs(process.argv.slice(2));
  for (const req of ["app", "channel", "platform", "build", "seq", "schema-head", "shell-min", "tree", "out", "key-env"]) {
    if (args[req] === undefined) fail(`--${req} is required`);
  }
  const { app, channel, platform, build } = args;
  const seq = parseInt(args.seq, 10);
  const schemaHead = parseInt(args["schema-head"], 10);
  const shellMin = parseInt(args["shell-min"], 10);
  const tree = path.resolve(args.tree);
  const out = path.resolve(args.out);
  const rollout = args.rollout !== undefined ? parseInt(args.rollout, 10) : 100;
  if (!Number.isInteger(seq) || !Number.isInteger(schemaHead) || !Number.isInteger(shellMin) || !Number.isInteger(rollout)) {
    fail("--seq, --schema-head, --shell-min and --rollout must be integers");
  }

  const have = new Set();
  if (args.have) {
    for (const line of fs.readFileSync(path.resolve(args.have), "utf8").split(/\r?\n/)) {
      const h = line.trim();
      if (h) have.add(h);
    }
  }

  const pulsePath = path.join(out, "p", app, channel, platform, "pulse.json");
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
  const manifestBytes = Buffer.from(JSON.stringify(manifest));
  const manifestHash = createHash("sha256").update(manifestBytes).digest("hex");
  const manifestPath = path.join(out, "p", "m", `${manifestHash}.json`);
  fs.mkdirSync(path.dirname(manifestPath), { recursive: true });
  const manifestTmp = `${manifestPath}.tmp`;
  fs.writeFileSync(manifestTmp, manifestBytes);
  fs.renameSync(manifestTmp, manifestPath);

  const pulseDoc = {
    app, channel, platform, build, seq,
    manifest: manifestHash,
    shell_min: shellMin,
    schema_head: schemaHead,
    rollout,
    paused: !!args.paused,
    issued: new Date().toISOString(),
    ...(args.rollback ? { rollback: args.rollback } : {}),
  };

  const keyRaw = process.env[args["key-env"]];
  if (!keyRaw) fail(`env var ${args["key-env"]} is not set`);
  let keyId;
  let privatePem;
  try {
    ({ key_id: keyId, private_key: privatePem } = JSON.parse(keyRaw));
  } catch {
    fail(`${args["key-env"]} must be JSON: {"key_id": "...", "private_key": "<pem>"}`);
  }
  if (!keyId || !privatePem) fail(`${args["key-env"]} must include both key_id and private_key`);

  const pulseBody = { signed: pulseDoc, signature: signDocument(PULSE_DOMAIN, pulseDoc, privatePem, keyId) };
  fs.mkdirSync(path.dirname(pulsePath), { recursive: true });
  const pulseTmp = `${pulsePath}.tmp`;
  fs.writeFileSync(pulseTmp, JSON.stringify(pulseBody));
  fs.renameSync(pulseTmp, pulsePath);

  console.log(`published ${app}/${channel}/${platform} build ${build} seq ${seq}: ${written.size} new blob(s), manifest ${manifestHash}`);
}

main().catch((err) => fail(err.stack || err.message));
