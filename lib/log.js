"use strict";
// Size-capped rotating file log: <dir>/<name>.log, then <name>.1.log … <name>.<keep-1>.log
// (newest first). Synchronous appends — the log must survive the crash that
// follows the line. Never throws: a log that cannot write must not take the app down.
const fs = require("node:fs");
const path = require("node:path");

function createLog({ dir, name = "app", maxBytes = 1024 * 1024, keep = 3, now = () => new Date() }) {
  const file = (i) => path.join(dir, i === 0 ? `${name}.log` : `${name}.${i}.log`);

  function rotate() {
    fs.rmSync(file(keep - 1), { force: true });
    for (let i = keep - 2; i >= 0; i--) if (fs.existsSync(file(i))) fs.renameSync(file(i), file(i + 1));
  }

  function write(level, msg) {
    try {
      fs.mkdirSync(dir, { recursive: true });
      const line = `${now().toISOString()} ${level} ${String(msg).replace(/\r?\n/g, "\n  ")}\n`;
      let size = 0;
      try { size = fs.statSync(file(0)).size; } catch { /* no file yet */ }
      if (size > 0 && size + Buffer.byteLength(line) > maxBytes) rotate();
      fs.appendFileSync(file(0), line);
    } catch {
      // ponytail: a failing log is silent by design (it cannot log its own failure); surface in the app UI if it ever matters.
    }
  }

  const fmt = (a) => a.map((x) => (x instanceof Error ? x.stack || x.message : typeof x === "string" ? x : JSON.stringify(x))).join(" ");
  return {
    path: file(0),
    info: (...a) => write("INFO", fmt(a)),
    warn: (...a) => write("WARN", fmt(a)),
    error: (...a) => write("ERROR", fmt(a)),
  };
}

module.exports = { createLog };
