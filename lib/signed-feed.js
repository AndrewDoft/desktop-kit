"use strict";
// Ed25519 over DOMAIN || canonical JSON. node:crypto only. The DOMAIN is the
// app's, passed in: a signature for one document kind is never valid as another.
// canonical = sorted keys, compact separators, non-ASCII left as-is
// (Python's json.dumps(sort_keys=True, separators=(",",":"), ensure_ascii=False)).
//
// Two feed layouts verify, both with the same envelope
// { algorithm:"ed25519", key_id, signature:<base64, 64 bytes> }:
//   Masora  { signed:  <doc>, signature }
//   Zevet   { payload: <doc>, signature }
// Legacy unsigned top-level fields are never read.
const crypto = require("node:crypto");

// DER prefix of an ed25519 SubjectPublicKeyInfo; the raw key follows.
const SPKI_PREFIX = Buffer.from("302a300506032b6570032100", "hex");

// ponytail: keys sort by UTF-16 unit, Python by code point — identical below U+10000.
function canonicalize(v) {
  if (Array.isArray(v)) return `[${v.map(canonicalize).join(",")}]`;
  if (v && typeof v === "object") {
    return `{${Object.keys(v).sort().map((k) => `${JSON.stringify(k)}:${canonicalize(v[k])}`).join(",")}}`;
  }
  const s = JSON.stringify(v);
  if (s === undefined) throw new Error("cannot canonicalize a non-JSON value");
  return s;
}

const signedBytes = (domain, doc) => Buffer.concat([Buffer.from(domain), Buffer.from(canonicalize(doc), "utf8")]);

function publicKeyObject(rawBase64) {
  const raw = Buffer.from(rawBase64, "base64");
  if (raw.length !== 32) throw new Error("public key is not 32 bytes");
  return crypto.createPublicKey({ key: Buffer.concat([SPKI_PREFIX, raw]), format: "der", type: "spki" });
}

/** Throws unless `envelope` is a valid signature over `doc` by a key in `keys`
 *  (`{ keyId: raw 32-byte key, base64 }` — several ids allow rotation).
 *  Returns the key id. No fallback: callers treat a throw as "reject". */
function verifySigned(domain, doc, envelope, keys) {
  if (!doc || typeof doc !== "object" || Array.isArray(doc)) throw new Error("signed document is not an object");
  if (!envelope || typeof envelope !== "object") throw new Error("the feed is not signed");
  if (envelope.algorithm !== "ed25519") throw new Error("signature algorithm must be ed25519");
  const id = envelope.key_id;
  if (typeof id !== "string" || !keys || !Object.hasOwn(keys, id)) throw new Error(`signed by an untrusted key (${JSON.stringify(id)})`);
  if (typeof envelope.signature !== "string" || !/^[A-Za-z0-9+/]{86}==$/.test(envelope.signature)) {
    throw new Error("signature is not 64 bytes of base64");
  }
  const ok = crypto.verify(null, signedBytes(domain, doc), publicKeyObject(keys[id]), Buffer.from(envelope.signature, "base64"));
  if (!ok) throw new Error("signature does not match the document");
  return id;
}

/** Verify a feed body and return its signed document. `field` pins the layout
 *  ("signed" or "payload"); omitted, either is accepted. */
function verifyFeed(body, domain, keys, field) {
  if (!body || typeof body !== "object") throw new Error("the feed is not signed");
  const doc = field ? body[field] : body.signed ?? body.payload;
  if (!doc || !body.signature) throw new Error("the feed is not signed");
  verifySigned(domain, doc, body.signature, keys);
  return doc;
}

/** Publisher side. `privatePem` is the PEM of the ed25519 key, `keyId` its pinned id. */
function signDocument(domain, doc, privatePem, keyId) {
  const sig = crypto.sign(null, signedBytes(domain, doc), crypto.createPrivateKey(privatePem));
  return { algorithm: "ed25519", key_id: keyId, signature: sig.toString("base64") };
}

module.exports = { canonicalize, verifySigned, verifyFeed, signDocument };
