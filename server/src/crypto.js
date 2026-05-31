// Ed25519 signing/verification + canonical JSON.
//
// This MUST stay byte-compatible with the Flutter app's CryptoService:
//   * key derivation: seed32 = sha256(utf8(seedPhrase)); Ed25519 from that seed
//   * canonical JSON: recursively key-sorted, compact, primitives via JSON encode
// Ed25519 (RFC 8032) is deterministic, so identical seed + identical message
// bytes yield identical public keys and signatures across Dart and Node.
import * as ed from '@noble/ed25519';
import { sha256 } from '@noble/hashes/sha256';
import { sha512 } from '@noble/hashes/sha512';

// @noble/ed25519 v2 needs a sha512 implementation wired in for sync APIs.
ed.etc.sha512Sync = (...m) => sha512(ed.etc.concatBytes(...m));

/** Deterministic 32-byte Ed25519 seed from a passphrase. */
export function seedBytes(seedPhrase) {
  return sha256(new TextEncoder().encode(seedPhrase));
}

/** Recursively key-sorted, compact JSON — mirrors Dart's canonicalize(). */
export function canonicalize(value) {
  if (value === null || value === undefined) return 'null';
  if (Array.isArray(value)) {
    return '[' + value.map(canonicalize).join(',') + ']';
  }
  if (typeof value === 'object') {
    const keys = Object.keys(value).sort();
    return (
      '{' +
      keys.map((k) => JSON.stringify(k) + ':' + canonicalize(value[k])).join(',') +
      '}'
    );
  }
  return JSON.stringify(value); // string / number / boolean
}

export function publicKeyBase64(seedPhrase) {
  const pub = ed.getPublicKey(seedBytes(seedPhrase));
  return Buffer.from(pub).toString('base64');
}

/** Sign a JSON-able payload; returns base64 signature. */
export function sign(payload, seedPhrase) {
  const msg = new TextEncoder().encode(canonicalize(payload));
  const sig = ed.sign(msg, seedBytes(seedPhrase));
  return Buffer.from(sig).toString('base64');
}

/** Verify base64 signature over a payload against a base64 public key. */
export function verify(payload, signatureB64, publicKeyB64) {
  try {
    const msg = new TextEncoder().encode(canonicalize(payload));
    const sig = Buffer.from(signatureB64, 'base64');
    const pub = Buffer.from(publicKeyB64, 'base64');
    return ed.verify(sig, msg, pub);
  } catch {
    return false;
  }
}

export function sha256Hex(text) {
  return Buffer.from(sha256(new TextEncoder().encode(text))).toString('hex');
}
