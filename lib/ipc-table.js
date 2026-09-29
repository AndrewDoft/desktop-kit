"use strict";
// One IPC table -> the preload bridge, its .d.ts, and the main-process handler
// registration check. The three used to be hand-synced copies.
//
//   defineIpc({
//     global: "zevet",                       // window.zevet
//     typeName: "ZevetBridge",               // .d.ts interface name (default: <Global>Bridge)
//     header: "prose",                       // comment at the top of the generated preload (first table's wins per table)
//     dtsHeader: 'import type { X } from "./x";',   // verbatim at the top of the .d.ts
//     prelude: "function helper() {}",       // verbatim JS placed just before this table's exposeInMainWorld
//     declareWindow: true,                   // false: no `declare global { interface Window … }` in the .d.ts
//     constants: { available: { value: true, type: "boolean" } },
//     calls: {                               // renderer -> main, ipcRenderer.invoke
//       test: { channel: "zevet:test", params: [["hub", "string"], ["token", "string"]],
//               pack: "object", returns: "Promise<{ ok: boolean }>", doc: "…" },
//       read: { channel: "local:read", params: ["root", "relPath"], pack: "object",
//               type: "(root: string, relPath: string) => Promise<R>", optional: true },
//     },
//     events: {                              // main -> renderer push; returns an unsubscribe
//       onUpdate: { channel: "app:update", payload: "UpdateStatus", doc: "…" },
//     },
//   })
//
// params: `[name, type]` pairs, or bare names when `type` gives the whole function type.
// pack: "spread" (default) sends the params as separate invoke args;
//       "object" sends one `{ a, b }` object keyed by the param names.
// payload: a JS expression sent as the single invoke argument instead (author-written, trusted).
// events: `transform` is a JS expression over `payload` handed to the listener instead of it;
//         `type` is the whole listener-registration type and `returns` its return (default `() => void`).
// Type strings are the author's, verbatim: the table is the only place they live.

const IDENT = /^[A-Za-z_$][\w$]*$/;
const CHANNEL = /^[A-Za-z0-9:_./-]+$/;

function defineIpc(spec) {
  if (!spec || !IDENT.test(spec.global || "")) throw new Error("defineIpc: `global` must be an identifier");
  const calls = spec.calls || {};
  const events = spec.events || {};
  const channels = new Map();
  const claim = (name, channel) => {
    if (!IDENT.test(name)) throw new Error(`defineIpc: "${name}" is not an identifier`);
    if (typeof channel !== "string" || !CHANNEL.test(channel)) throw new Error(`defineIpc: ${name}: bad channel ${JSON.stringify(channel)}`);
    if (channels.has(channel)) throw new Error(`defineIpc: channel "${channel}" is used by both ${channels.get(channel)} and ${name}`);
    channels.set(channel, name);
  };
  for (const [name, c] of Object.entries(calls)) {
    claim(name, c.channel);
    if (typeof c.type !== "string" && typeof c.returns !== "string") throw new Error(`defineIpc: ${name}: \`returns\` (or a whole \`type\`) is required`);
    if (c.pack !== undefined && c.pack !== "spread" && c.pack !== "object") throw new Error(`defineIpc: ${name}: pack must be "spread" or "object"`);
    for (const p of c.params || []) {
      const ok = typeof p === "string" ? IDENT.test(p) : Array.isArray(p) && IDENT.test(p[0]) && typeof p[1] === "string";
      if (!ok) throw new Error(`defineIpc: ${name}: params are names or [name, type] pairs`);
      if (typeof p === "string" && typeof c.type !== "string") throw new Error(`defineIpc: ${name}: a bare param name needs a whole \`type\``);
    }
  }
  for (const [name, e] of Object.entries(events)) {
    claim(name, e.channel);
    if (typeof e.type !== "string" && typeof e.payload !== "string") throw new Error(`defineIpc: ${name}: \`payload\` type (or a whole \`type\`) is required`);
  }
  for (const n of Object.keys(spec.constants || {})) if (!IDENT.test(n) || n in calls || n in events) throw new Error(`defineIpc: bad constant ${n}`);
  if (Object.keys(calls).some((n) => n in events)) throw new Error("defineIpc: a name is both a call and an event");
  const typeName = spec.typeName || `${spec.global[0].toUpperCase()}${spec.global.slice(1)}Bridge`;
  return Object.freeze({
    global: spec.global, typeName, header: spec.header || "", dtsHeader: spec.dtsHeader || "", prelude: spec.prelude || "",
    declareWindow: spec.declareWindow !== false, constants: spec.constants || {}, calls, events,
  });
}

const asList = (t) => (Array.isArray(t) ? t : [t]);
const paramName = (p) => (typeof p === "string" ? p : p[0]);

/** A doc string as a `/** … *​/` block at `indent` (single-line stays single-line). */
function doc(text, indent) {
  if (!text) return "";
  const body = String(text).replace(/\*\//g, "* /").split("\n");
  if (body.length === 1) return `${indent}/** ${body[0]} */\n`;
  return `${indent}/**\n${body.map((l) => `${indent} * ${l}`.replace(/\s+$/, "")).join("\n")}\n${indent} */\n`;
}

const lineComment = (text) => String(text).split("\n").map((l) => `// ${l}`.replace(/\s+$/, "")).join("\n");

/** Source of a CommonJS preload script exposing one `window.<global>` per table. */
function generatePreload(tables) {
  const list = asList(tables);
  const blocks = list.map((table) => {
    const lines = [];
    for (const [name, v] of Object.entries(table.constants)) lines.push(`  ${name}: ${JSON.stringify(v.value)},`);
    for (const [name, c] of Object.entries(table.calls)) {
      const names = (c.params || []).map(paramName);
      const args = c.payload ?? (c.pack === "object" && names.length ? `{ ${names.join(", ")} }` : names.join(", "));
      lines.push(`${doc(c.doc, "  ")}  ${name}: (${names.join(", ")}) => ipcRenderer.invoke(${JSON.stringify(c.channel)}${args ? `, ${args}` : ""}),`);
    }
    for (const [name, e] of Object.entries(table.events)) {
      const sub = e.transform
        ? `subscribe(${JSON.stringify(e.channel)}, (payload) => fn(${e.transform}))`
        : `subscribe(${JSON.stringify(e.channel)}, fn)`;
      lines.push(`${doc(e.doc, "  ")}  ${name}: (fn) => ${sub},`);
    }
    return `${table.prelude ? `${table.prelude}\n\n` : ""}contextBridge.exposeInMainWorld(${JSON.stringify(table.global)}, {\n${lines.join("\n")}\n});\n`;
  });
  const headers = list.map((t) => t.header).filter(Boolean).map(lineComment).join("\n//\n");
  return `// GENERATED by @masora/desktop-kit from the IPC table. Do not edit; change the table.
${headers ? `//\n${headers}\n` : ""}"use strict";
const { contextBridge, ipcRenderer } = require("electron");

/** Subscribe to a main-process push; returns the way to stop. */
function subscribe(channel, fn) {
  const handler = (_e, payload) => fn(payload);
  ipcRenderer.on(channel, handler);
  return () => ipcRenderer.removeListener(channel, handler);
}

${blocks.join("\n")}`;
}

/** Source of the .d.ts: one interface per table. */
function generateDts(tables) {
  const list = asList(tables);
  const interfaces = [];
  for (const table of list) {
    const lines = [];
    for (const [name, v] of Object.entries(table.constants)) lines.push(`  ${name}: ${v.type};`);
    for (const [name, c] of Object.entries(table.calls)) {
      const q = c.optional ? "?" : "";
      if (typeof c.type === "string") {
        lines.push(`${doc(c.doc, "  ")}  ${name}${q}: ${c.type};`);
      } else {
        const params = (c.params || []).map(([n, t]) => `${n}: ${t}`).join(", ");
        lines.push(`${doc(c.doc, "  ")}  ${name}${q}(${params}): ${c.returns};`);
      }
    }
    for (const [name, e] of Object.entries(table.events)) {
      const q = e.optional ? "?" : "";
      const ret = e.returns || "() => void";
      lines.push(typeof e.type === "string"
        ? `${doc(e.doc, "  ")}  ${name}${q}: ${e.type};`
        : `${doc(e.doc, "  ")}  ${name}${q}: (fn: (payload: ${e.payload}) => void) => ${ret};`);
    }
    interfaces.push(`export interface ${table.typeName} {\n${lines.join("\n")}\n}\n`);
  }
  const globals = list.filter((t) => t.declareWindow).map((t) => `    ${t.global}: ${t.typeName};`);
  const headers = [...new Set(list.map((t) => t.dtsHeader).filter(Boolean))].join("\n");
  return `// GENERATED by @masora/desktop-kit from the IPC table. Do not edit; change the table.
${headers ? `${headers}\n` : ""}
${interfaces.join("\n")}${globals.length ? `\ndeclare global {\n  interface Window {\n${globals.join("\n")}\n  }\n}\n` : ""}`;
}

const callMap = (tables) => {
  const m = new Map();
  for (const t of asList(tables)) for (const [name, c] of Object.entries(t.calls)) {
    if (m.has(c.channel)) throw new Error(`IPC tables share channel "${c.channel}"`);
    m.set(c.channel, `${t.global}.${name}`);
  }
  return m;
};

/** Register `handlers` (name -> fn(event, ...args)) on ipcMain for every call in
 *  one table. Throws on a call with no handler or a handler with no call. */
function registerIpc(ipcMain, table, handlers) {
  const missing = Object.keys(table.calls).filter((n) => typeof handlers[n] !== "function");
  const extra = Object.keys(handlers).filter((n) => !(n in table.calls));
  if (missing.length || extra.length) {
    throw new Error(`registerIpc: table/handler drift — no handler for [${missing}], no call for [${extra}]`);
  }
  for (const [name, c] of Object.entries(table.calls)) ipcMain.handle(c.channel, handlers[name]);
}

/** Registry for handlers spread across a large main file. `handle(channel, fn)`
 *  refuses a channel that is not a call in the tables or is registered twice;
 *  `assertComplete()` throws listing every table call nobody handled.
 *  `ipcMain.handle` is looked up per call, so a guard patched onto it earlier still applies. */
function createIpcRegistry(ipcMain, tables) {
  const calls = callMap(tables);
  const done = new Set();
  return {
    handle(channel, fn) {
      if (!calls.has(channel)) throw new Error(`ipc ${channel}: not in the IPC table`);
      if (done.has(channel)) throw new Error(`ipc ${channel}: registered twice`);
      done.add(channel);
      return ipcMain.handle(channel, fn);
    },
    assertComplete() {
      const missing = [...calls].filter(([c]) => !done.has(c)).map(([c, n]) => `${n} (${c})`);
      if (missing.length) throw new Error(`the IPC table lists calls main never handled: ${missing.join(", ")}`);
    },
  };
}

module.exports = { defineIpc, generatePreload, generateDts, registerIpc, createIpcRegistry };
