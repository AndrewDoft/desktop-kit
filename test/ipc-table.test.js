"use strict";
const { test } = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const vm = require("node:vm");
const { spawnSync } = require("node:child_process");
const { defineIpc, generatePreload, generateDts, registerIpc } = require("..");

const table = defineIpc({
  global: "demo",
  dtsHeader: 'import type { Status } from "./status";',
  calls: {
    config: { channel: "demo:config", returns: "Promise<{ hub: string } | null>", doc: "The saved settings." },
    test: { channel: "demo:test", params: [["hub", "string"], ["token", "string"]], pack: "object", returns: "Promise<{ ok: boolean }>" },
    send: { channel: "demo:send", params: [["room", "string"], ["n", "number"]], returns: "Promise<void>" },
  },
  events: { onUpdate: { channel: "app:update", payload: "Status", doc: "Updater phase." } },
});

/** Run the generated preload against a fake electron and return the exposed bridge + the ipc log. */
function load() {
  const invoked = [];
  const listeners = new Map();
  let exposed;
  const electron = {
    contextBridge: { exposeInMainWorld: (name, api) => { exposed = { name, api }; } },
    ipcRenderer: {
      invoke: (ch, ...a) => { invoked.push([ch, ...a]); return Promise.resolve("r"); },
      on: (ch, h) => listeners.set(ch, h),
      removeListener: (ch, h) => { if (listeners.get(ch) === h) listeners.delete(ch); },
    },
  };
  vm.runInNewContext(generatePreload(table), { require: (m) => { assert.equal(m, "electron"); return electron; } });
  return { exposed, invoked, listeners };
}

test("generated preload: exposes window.<global>, invoke packs per spec, events return an unsubscribe", async () => {
  const { exposed, invoked, listeners } = load();
  assert.equal(exposed.name, "demo");
  assert.deepEqual(Object.keys(exposed.api).sort(), ["config", "onUpdate", "send", "test"]);
  await exposed.api.config();
  await exposed.api.test("h", "t");
  await exposed.api.send("room", 3);
  assert.deepEqual(JSON.parse(JSON.stringify(invoked)), [["demo:config"], ["demo:test", { hub: "h", token: "t" }], ["demo:send", "room", 3]]);
  const got = [];
  const off = exposed.api.onUpdate((p) => got.push(p));
  listeners.get("app:update")({}, { phase: "ready" });
  assert.deepEqual(JSON.parse(JSON.stringify(got)), [{ phase: "ready" }]);
  off();
  assert.equal(listeners.has("app:update"), false);
});

test("generated .d.ts carries every call and event with the author's types", () => {
  const dts = generateDts(table);
  assert.match(dts, /import type \{ Status \} from "\.\/status";/);
  assert.match(dts, /export interface DemoBridge \{/);
  assert.match(dts, /config\(\): Promise<\{ hub: string \} \| null>;/);
  assert.match(dts, /test\(hub: string, token: string\): Promise<\{ ok: boolean \}>;/);
  assert.match(dts, /send\(room: string, n: number\): Promise<void>;/);
  assert.match(dts, /onUpdate\(fn: \(payload: Status\) => void\): \(\) => void;/);
  assert.match(dts, /demo: DemoBridge;/);
  assert.match(dts, /\/\*\* The saved settings\. \*\//);
});

test("defineIpc refuses duplicate channels, bad names, bad pack, missing types", () => {
  const base = { global: "g", calls: { a: { channel: "x:a", returns: "Promise<void>" } } };
  assert.throws(() => defineIpc({ ...base, events: { onA: { channel: "x:a", payload: "T" } } }), /used by both/);
  assert.throws(() => defineIpc({ global: "g", calls: { "a b": { channel: "x:a", returns: "T" } } }), /not an identifier/);
  assert.throws(() => defineIpc({ global: "g", calls: { a: { channel: "x:a", returns: "T", pack: "wat" } } }), /pack/);
  assert.throws(() => defineIpc({ global: "g", calls: { a: { channel: "x:a" } } }), /returns/);
  assert.throws(() => defineIpc({ global: "1g", calls: {} }), /global/);
});

test("registerIpc registers every call and refuses table/handler drift", () => {
  const reg = [];
  const ipcMain = { handle: (ch, fn) => reg.push([ch, fn]) };
  const fn = () => 1;
  registerIpc(ipcMain, table, { config: fn, test: fn, send: fn });
  assert.deepEqual(reg.map((r) => r[0]), ["demo:config", "demo:test", "demo:send"]);
  assert.throws(() => registerIpc(ipcMain, table, { config: fn, test: fn }), /no handler for \[send\]/);
  assert.throws(() => registerIpc(ipcMain, table, { config: fn, test: fn, send: fn, extra: fn }), /no call for \[extra\]/);
});

test("CLI: writes the files, --check passes when current and fails (exit 1) when stale", () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "kit-ipc-"));
  const tableFile = path.join(dir, "table.js");
  fs.writeFileSync(tableFile, `module.exports = require(${JSON.stringify(path.resolve(__dirname, ".."))}).defineIpc({ global: "cli", calls: { ping: { channel: "cli:ping", returns: "Promise<void>" } } });`);
  const run = (...a) => spawnSync(process.execPath, [path.resolve(__dirname, "../bin/ipc-gen.js"), tableFile, "--preload", path.join(dir, "preload.js"), "--dts", path.join(dir, "b.d.ts"), ...a], { encoding: "utf8" });
  assert.equal(run("--check").status, 1, "absent outputs are stale");
  assert.equal(run().status, 0);
  assert.equal(run("--check").status, 0);
  fs.appendFileSync(path.join(dir, "preload.js"), "// hand edit\n");
  const stale = run("--check");
  assert.equal(stale.status, 1);
  assert.match(stale.stderr, /out of date/);
});
