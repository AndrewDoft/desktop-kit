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
| `ipc-table` | `defineIpc(table)` → `generatePreload`, `generateDts`, `registerIpc`; CLI `desktop-kit-ipc table.js --preload p.js --dts b.d.ts [--check]` |

Consume as `"@masora/desktop-kit": "github:AndrewDoft/desktop-kit#v0.1.0"`.
No keys live here; public keys are passed in by each app. `npm test` runs the suite.
