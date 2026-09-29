#!/usr/bin/env node
"use strict";
// desktop-kit-ipc <table.js> --preload <out.js> --dts <out.d.ts> [--check]
// <table.js> exports a defineIpc() table, an array of them, or an object of them. --check writes nothing and exits 1 if
// either output differs from what is on disk (for CI: the generated files are committed).
const fs = require("node:fs");
const path = require("node:path");
const { generatePreload, generateDts } = require("../lib/ipc-table.js");

const args = process.argv.slice(2);
const flag = (n) => (args.includes(n) ? args[args.indexOf(n) + 1] : null);
const tableFile = args.find((a) => !a.startsWith("--") && a !== flag("--preload") && a !== flag("--dts"));
const check = args.includes("--check");
if (!tableFile || (!flag("--preload") && !flag("--dts"))) {
  console.error("usage: desktop-kit-ipc <table.js> [--preload out.js] [--dts out.d.ts] [--check]");
  process.exit(2);
}
const mod = require(path.resolve(tableFile));
// a table, an array of tables, or an object whose values (or .tables) are tables
const table = mod.global ? mod : Array.isArray(mod) ? mod : Array.isArray(mod.tables) ? mod.tables : Object.values(mod.tables || mod);
let stale = 0;
for (const [out, src] of [[flag("--preload"), generatePreload(table)], [flag("--dts"), generateDts(table)]]) {
  if (!out) continue;
  let have = null;
  try { have = fs.readFileSync(out, "utf8"); } catch { /* absent */ }
  if (have === src) continue;
  if (check) {
    console.error(`${out}: out of date with ${tableFile}`);
    stale++;
  } else {
    fs.mkdirSync(path.dirname(path.resolve(out)), { recursive: true });
    fs.writeFileSync(out, src);
    console.log(`wrote ${out}`);
  }
}
process.exit(stale ? 1 : 0);
