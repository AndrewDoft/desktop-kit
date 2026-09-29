# @masora/desktop-kit

Electron plumbing for bespoke desktop apps. CommonJS, zero runtime dependencies
(`node:` built-ins only); `electron` is an optional peer.

```js
const kit = require("@masora/desktop-kit");
```

| Module | What |
|---|---|
| `signed-feed` | `verifyFeed(body, domain, keys[, field])`, `verifySigned`, `signDocument`, `canonicalize`. Ed25519 over `domain \|\| canonical JSON`; several key ids; `{signed, signature}` and `{payload, signature}` layouts. The domain and keys belong to each app. |
| `updater` | `UpdaterCore`: check → download → sha256 → ready → install / install-on-quit. Platform steps injected via `steps: { restart, onQuit, publisherProblem }`. |
| `single-instance` | `singleInstance(app, onSecond)` |
| `safe-open` | `isSafeUrl`, `openSafe` — https, or http to loopback only |
| `ipc-guard` | `senderAllowed(url, {origins, files, anyFile})`, `guardIpc(ipcMain, policy, denied?)` |
| `log` | `createLog({dir, name, maxBytes, keep})` — size-capped rotating file log |
| `ipc-table` | `defineIpc(table)` (one table per `window` global; several go into one preload) → `generatePreload`, `generateDts`, `registerIpc`, `createIpcRegistry`; CLI `desktop-kit-ipc table.js --preload p.js --dts b.d.ts [--check]` |
| `family` | the per-user family dir Masora/Zevet/Voice pair through: `familyDir`, `readJson`, `writeJsonAtomic`, `readKey`/`ensureKey` (user-only), `masoraWeb`, heartbeats (`writeHeartbeat`/`readHeartbeat`/`isRunning`), requests (`writeRequest`/`takeRequest`). On-disk format is what shipped apps write; Voice (Python) reads the same files. |
| `payload` | content-addressed payload client + publisher — see below |

Consume as `"@masora/desktop-kit": "github:AndrewDoft/desktop-kit#v0.2.0"`.
No keys live here; public keys are passed in by each app. `npm test` runs the suite.

## Payload

A hot-swappable, content-addressed build tree: the client downloads only files whose hash it
does not already hold (from its local store or the installer's seed), materialises them by
hardlink, and swaps `current.json` to activate — no reinstall.

```js
const { createPayloadClient, hashTree } = require("@masora/desktop-kit/lib/payload");

const payload = createPayloadClient({
  app, channel, platform,        // e.g. "masora-context", "stable", "win-x64"
  root,                          // <LOCALAPPDATA>/<App>/payload
  seedDir, seedBuild, seedSeq,   // the installer's bundled tree, or null
  pulseUrl,                      // .../p/<app>/<channel>/<platform>/pulse.json
  keys,                          // pinned {keyId: base64 ed25519 public key} (signed-feed.js's shape)
  shellVersion, schemaHead,      // integer; async () => integer|null
  installId,                     // stable per install, for rollout bucketing
  fetch, log,                    // injectable
});

payload.resolve();          // SYNC, at boot -> { dir, build, seq, source: "current"|"previous"|"seed", trial }
await payload.check();      // -> { status: "none"|"staged"|"refused"|"paused"|"not-in-rollout"|"needs-shell", build?, reason? }
payload.staged();           // -> { build, seq, dir, schemaHead, shellMin } | null
await payload.activate();   // staged -> current, as a trial -> { dir, build, previous }; re-checks bad-list/shell_min/schemaHead
payload.confirm();          // trial -> confirmed; also runs gc()
payload.bootFailed(reason); // 3 strikes -> auto-revert; -> { reverted, dir }
payload.revert(reason);     // immediate revert to previous; bad-lists the build
payload.verifyEntry(relPaths); // re-verifies the signed pulse + manifest, then re-hashes; throws on mismatch
payload.gc();                  // keep exactly {current, previous, staged}; sweep unreferenced blobs and day-old .partial files
payload.start({ everyMs }); payload.stop(); // periodic check(), emits "staged"
hashTree(dir);               // -> manifest `files` array; used by the publisher and seed mapping; throws on a symlink
```

On-disk layout under `root`:

```
store/<sha[0:2]>/<sha>            verified blobs (decompressed), read-only
versions/<build>/...              materialised by hardlink from the store (copy fallback)
versions/<build>/.pulse.json      the raw signed pulse bytes that named this build
versions/<build>/.manifest.raw    the raw manifest bytes, hash-bound to .pulse.json
versions/<build>/.complete        written last; its presence means the tree is runnable
current.json                {build, seq, previous:{build,seq}|null, trial, trial_started, boots, failures,
                              high_seq, high_seq_build, high_seq_manifest, high_seq_issued}
bad.json                    {builds:[...]} — never re-applied
staged.json                 the verified+materialised build waiting on activate()
seed-index.json             the seed's cached hash tree, keyed by seedBuild
```

`resolve()` and `verifyEntry()` never trust `.manifest.raw` on its own: they re-verify
`.pulse.json`'s signature and that `sha256(.manifest.raw)` matches the signed pulse's `manifest`
field, so editing a tree file and the manifest together (without the signing key) no longer
passes. `current.json`'s `high_seq*` fields are a floor that only moves forward, independent of
`seq` (which moves backward on a rollback) — replaying an old, validly-signed pulse can never
re-stage a build once a higher seq has been seen.

Wire format (`https://.../p/`): `<app>/<channel>/<platform>/pulse.json` (the signed pulse:
`{app, channel, platform, build, seq, manifest, shell_min, schema_head, rollout, paused, issued}`,
same envelope as `signed-feed.js`), `m/<sha256>.json` (manifest), `b/<sha[0:2]>/<sha256>` (a
brotli-compressed blob, hash-bound to the raw decompressed bytes).

Publish with `bin/publish-payload.mjs`:

```
node desktop-kit/bin/publish-payload.mjs --app --channel --platform --build --seq \
  --schema-head --shell-min --tree <dir> --out <staging dir> --key-env <ENV VAR> --key-id <id> \
  [--have <file of blob hashes already on the server>] [--rollout N] [--paused] [--rollback <build>]
```

Walks `--tree` with `hashTree`, brotli(q9)-compresses every blob not listed in `--have`, and
writes the `p/` layout (new blobs, manifest, pulse) under `--out`. `--key-env` names an env var
holding the raw ed25519 PKCS8 PEM (newlines optionally encoded as `|`, as in `MASORA_UPDATE_SIGNING_KEY`); `--key-id` is its pinned id; the pulse is signed the same way
`signed-feed.js` verifies it. Refuses to write a pulse whose `seq` is <= one already staged in
`--out` for the same app/channel/platform. An optional `<tree>/entry.json` becomes the
manifest's `entry` field.

Ops subcommands re-sign a pulse in `--out` (a local mirror of the server's `p/` tree) with no
rebuild; blobs and manifests are never touched and must already be in `--out/p/m`:

```
publish-payload.mjs promote  --app --platform --from canary --to stable --out <dir> [--rollout N]
publish-payload.mjs pause|resume --app --channel --platform --out <dir>
publish-payload.mjs rollback --app --channel --platform --to <build> --out <dir> [--manifest <sha256>]
```

(all take `--key-env`/`--key-id`). `seq` stays strictly increasing per channel: promote uses
`max(stable + 1, canary)`, rollback `current + 1` with `rollback` naming the build left; pause/resume
re-sign the same `seq` (a higher one would make clients re-stage the build they already run).
