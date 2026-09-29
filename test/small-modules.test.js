"use strict";
const { test } = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const { pathToFileURL } = require("node:url");
const { isSafeUrl, openSafe, senderAllowed, guardIpc, singleInstance, createLog } = require("..");

test("safe-open: https always, http only to this machine, nothing else", async () => {
  for (const u of ["https://example.com/x", "http://localhost:8080", "http://127.0.0.1/a", "http://[::1]:1/"]) assert.ok(isSafeUrl(u), u);
  for (const u of ["http://example.com", "file:///c:/x", "smb://h/s", "javascript:alert(1)", "zevet://x", "not a url", ""]) assert.ok(!isSafeUrl(u), u);
  assert.ok(isSafeUrl("http://intranet.local/", ["intranet.local"]));
  const opened = [];
  const shell = { openExternal: async (u) => { opened.push(u); return "ok"; } };
  assert.equal(await openSafe("https://a.example/", shell), "ok");
  await assert.rejects(openSafe("file:///etc/passwd", shell), /refusing/);
  assert.deepEqual(opened, ["https://a.example/"]);
});

test("ipc-guard: origins, exact files, anyFile", () => {
  const setup = path.resolve("/app/setup.html");
  const pol = { origins: ["https://hub.example/anything"], files: [setup] };
  assert.ok(senderAllowed("https://hub.example/board", pol));
  assert.ok(!senderAllowed("https://evil.example/board", pol));
  assert.ok(!senderAllowed("http://hub.example/board", pol));
  assert.ok(senderAllowed(pathToFileURL(setup).href, pol));
  assert.ok(!senderAllowed(pathToFileURL(path.resolve("/app/other.html")).href, pol));
  assert.ok(senderAllowed(pathToFileURL(path.resolve("/app/other.html")).href, { anyFile: true }));
  assert.ok(!senderAllowed("about:blank", { origins: ["null", ""] }));
  assert.ok(!senderAllowed(undefined, pol));
  assert.ok(!senderAllowed("https://hub.example/", { origins: [null] }));
});

test("ipc-guard: guardIpc wraps later registrations; denial throws or uses the supplied reply", async () => {
  const handlers = {};
  const ipcMain = { handle(ch, fn) { handlers[ch] = fn; } };
  guardIpc(ipcMain, () => ({ origins: ["https://hub.example"] }));
  ipcMain.handle("x", (_e, a) => a * 2);
  assert.equal(await handlers.x({ senderFrame: { url: "https://hub.example/p" } }, 4), 8);
  assert.throws(() => handlers.x({ senderFrame: { url: "https://evil.example/" } }, 4), /sender not allowed/);
  assert.throws(() => handlers.x({}, 4), /sender not allowed/);
  const m2 = { handle(ch, fn) { handlers[ch] = fn; } };
  guardIpc(m2, () => ({ origins: [] }), () => ({ ok: false, error: "failed" }));
  m2.handle("y", () => "secret");
  assert.deepEqual(handlers.y({ senderFrame: { url: "https://evil.example/" } }), { ok: false, error: "failed" });
});

test("single-instance: winner registers second-instance; loser quits", () => {
  const mk = (lock) => {
    const a = { quitCalled: false, handlers: {}, requestSingleInstanceLock: () => lock };
    a.quit = () => { a.quitCalled = true; };
    a.on = (e, f) => { a.handlers[e] = f; };
    return a;
  };
  let seen = 0;
  const win = mk(true);
  assert.equal(singleInstance(win, () => seen++), true);
  win.handlers["second-instance"]();
  assert.equal(seen, 1);
  assert.ok(!win.quitCalled);
  const lose = mk(false);
  assert.equal(singleInstance(lose, () => seen++), false);
  assert.ok(lose.quitCalled);
  assert.deepEqual(lose.handlers, {});
});

test("log: appends, rotates at the size cap, keeps N files newest-first, never throws", () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "kit-log-"));
  const log = createLog({ dir, name: "t", maxBytes: 200, keep: 3, now: () => new Date(0) });
  for (let i = 0; i < 30; i++) log.info(`line-${String(i).padStart(2, "0")} ${"x".repeat(30)}`);
  const files = fs.readdirSync(dir).sort();
  assert.deepEqual(files, ["t.1.log", "t.2.log", "t.log"]);
  for (const f of files) assert.ok(fs.statSync(path.join(dir, f)).size <= 200, f);
  const last = (f) => fs.readFileSync(path.join(dir, f), "utf8").trim().split("\n").at(-1);
  assert.match(last("t.log"), /line-29/);
  const n = (f) => Number(/line-(\d+)/.exec(last(f))[1]);
  assert.ok(n("t.log") > n("t.1.log") && n("t.1.log") > n("t.2.log"), "newest first");
  log.error(new Error("boom"));
  assert.match(fs.readFileSync(path.join(dir, "t.log"), "utf8"), /ERROR Error: boom/);
  // an unwritable directory (a file where the dir should be) must not throw
  const blocked = createLog({ dir: path.join(dir, "t.log", "sub"), name: "x" });
  assert.doesNotThrow(() => blocked.info("nope"));
});
