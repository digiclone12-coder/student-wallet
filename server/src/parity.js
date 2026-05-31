// Prints Ed25519 public key + signature for a fixed seed/payload so we can
// confirm byte-for-byte parity with the Flutter app's CryptoService.
import { publicKeyBase64, sign, canonicalize } from './crypto.js';

const seed = 'ndear-issuer-seed::swayam::v1';
const payload = { b: 'second', a: 1, nested: { y: [3, 2, 1], x: true } };

console.log('canonical:', canonicalize(payload));
console.log('publicKey:', publicKeyBase64(seed));
console.log('signature:', sign(payload, seed));
