"use strict";
const { test } = require("node:test");
const assert = require("node:assert/strict");
const { generateKeyPairSync } = require("node:crypto");
const { canonicalize, verifySigned, verifyFeed, signDocument } = require("..");

const ZEVET_DOMAIN = "zevet-update-v1\n";
// Zevet's real pinned public key (public data). Golden: signed once by the real key.
const ZEVET_KEYS = { "zevet-2026-09": "WtLCaM3MBForULoSLJ0tYRmPyr4fOv24wBbugXSahZc=" };
const live = require("./fixtures/zevet-latest-0.2.86.json");

function testKey(id = "test-1") {
  const { publicKey, privateKey } = generateKeyPairSync("ed25519");
  return { id, pem: privateKey.export({ format: "pem", type: "pkcs8" }), keys: { [id]: publicKey.export({ format: "der", type: "spki" }).subarray(-32).toString("base64") } };
}

test("canonical form: sorted keys, compact, non-ASCII untouched", () => {
  assert.equal(canonicalize({ b: 1, a: [3, { d: null, c: "héllo ✓" }], n: 1.5 }), '{"a":[3,{"c":"héllo ✓","d":null}],"b":1,"n":1.5}');
  assert.equal(canonicalize({ b: [1, { z: "é\n\"", a: null }], a: true }), '{"a":true,"b":[1,{"a":null,"z":"é\\n\\""}]}');
  assert.throws(() => canonicalize({ f: () => 1 }), /non-JSON/);
});

test("golden: the live Zevet feed {payload, signature} verifies against the real pinned key", () => {
  assert.equal(verifyFeed(live, ZEVET_DOMAIN, ZEVET_KEYS).version, "0.2.86");
  assert.equal(verifyFeed(live, ZEVET_DOMAIN, ZEVET_KEYS, "payload").version, "0.2.86");
  assert.throws(() => verifyFeed(live, ZEVET_DOMAIN, ZEVET_KEYS, "signed"), /not signed/);
});

test("golden: Zevet's real-key vector over a fixed document", () => {
  const doc = { version: "0.2.84", platforms: { "win32-x64": { bytes: 1, file: "x", sha256: "0".repeat(64) } }, schema: 1 };
  const sig = { algorithm: "ed25519", key_id: "zevet-2026-09", signature: "m464gnddVxaD26bT6ZIo4hQjIQIlwyjFBolFzjq00NNEgNGcpdlMl2hvo/4FkN8MVSBA5hE3lwpYyreiuEDHDg==" };
  assert.equal(verifySigned(ZEVET_DOMAIN, doc, sig, ZEVET_KEYS), "zevet-2026-09");
});

test("the live feed is refused for another domain, a tampered document and a foreign key", () => {
  assert.throws(() => verifyFeed(live, "masora-context-update-v1\n", ZEVET_KEYS), /does not match/);
  const t = structuredClone(live);
  t.payload.platforms["win32-x64"].sha256 = "0".repeat(64);
  assert.throws(() => verifyFeed(t, ZEVET_DOMAIN, ZEVET_KEYS), /does not match/);
  assert.throws(() => verifyFeed(live, ZEVET_DOMAIN, testKey("zevet-2026-09").keys), /does not match/);
  assert.throws(() => verifyFeed(live, ZEVET_DOMAIN, {}), /untrusted key/);
});

test("Masora layout {signed, signature} verifies; legacy top-level fields are never read", () => {
  const k = testKey();
  const domain = "masora-context-update-v1\n";
  const signed = { schema: 1, type: "feed", version: "9.0.0", platforms: {} };
  const feed = { version: "0.0.1", signed, signature: signDocument(domain, signed, k.pem, k.id) };
  assert.equal(verifyFeed(feed, domain, k.keys).version, "9.0.0");
  const { signed: _s, signature: _g, ...legacy } = feed;
  assert.throws(() => verifyFeed(legacy, domain, k.keys), /not signed/);
});

test("several key ids: either verifies, an unlisted id does not (rotation)", () => {
  const a = testKey("k-a");
  const b = testKey("k-b");
  const keys = { ...a.keys, ...b.keys };
  const doc = { v: 1 };
  assert.equal(verifySigned("d\n", doc, signDocument("d\n", doc, a.pem, "k-a"), keys), "k-a");
  assert.equal(verifySigned("d\n", doc, signDocument("d\n", doc, b.pem, "k-b"), keys), "k-b");
  assert.throws(() => verifySigned("d\n", doc, signDocument("d\n", doc, b.pem, "k-c"), keys), /untrusted key/);
  // a key id that is a prototype property is not a trusted key
  assert.throws(() => verifySigned("d\n", doc, signDocument("d\n", doc, a.pem, "toString"), keys), /untrusted key/);
});

test("malformed envelopes are refused", () => {
  const k = testKey();
  const doc = { v: 1 };
  const good = signDocument("d\n", doc, k.pem, k.id);
  assert.throws(() => verifySigned("d\n", doc, { ...good, algorithm: "rsa" }, k.keys), /ed25519/);
  assert.throws(() => verifySigned("d\n", doc, { ...good, signature: "AAAA" }, k.keys), /64 bytes/);
  assert.throws(() => verifySigned("d\n", [1], good, k.keys), /not an object/);
  assert.throws(() => verifySigned("d\n", doc, null, k.keys), /not signed/);
  assert.throws(() => verifyFeed(null, "d\n", k.keys), /not signed/);
});

test("the domain may be a Buffer", () => {
  const k = testKey();
  const sig = signDocument(Buffer.from("d\n"), { a: 1 }, k.pem, k.id);
  assert.equal(verifySigned("d\n", { a: 1 }, sig, k.keys), k.id);
});
