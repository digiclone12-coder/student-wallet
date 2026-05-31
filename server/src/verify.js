// Offline-style verification pipeline — mirrors the Flutter VerificationService.
import { verify as edVerify } from './crypto.js';

function extractIssuer(raw) {
  const i = raw.issuer;
  if (i && typeof i === 'object') return { id: i.id || '', name: i.name || '' };
  if (typeof i === 'string') return { id: i, name: i };
  return null;
}

function extractTitle(raw) {
  if (raw.title) return String(raw.title);
  const a = raw.credentialSubject?.achievement;
  if (a?.name) return String(a.name);
  const def = raw.object?.definition?.name;
  if (def && typeof def === 'object') return String(Object.values(def)[0]);
  return null;
}

function extractSubject(raw) {
  if (raw.credentialSubject?.name) return String(raw.credentialSubject.name);
  if (raw.recipient) return String(raw.recipient);
  if (raw.actor?.name) return String(raw.actor.name);
  return null;
}

function extractExpiry(raw) {
  const v = raw.validUntil || raw.expiryDate || raw.expires;
  return v ? new Date(v) : null;
}

/**
 * @param raw            credential document
 * @param issuerPubKeyById  map { issuerId -> publicKeyBase64 } (trusted registry)
 * @param revokedIds     Set of revoked credential ids
 */
export function verifyCredential(raw, issuerPubKeyById, revokedIds = new Set()) {
  const checks = [];
  const push = (label, passed, detail) => checks.push({ label, passed, detail });

  if (!raw || typeof raw !== 'object' || !raw.id) {
    push('Document is well-formed', false);
    return { status: 'malformed', checks };
  }
  push('Document is well-formed', true);

  const issuer = extractIssuer(raw);
  const title = extractTitle(raw);
  const subject = extractSubject(raw);

  const signature = raw.proof?.proofValue;
  const hasProof = !!signature;
  push('Carries a cryptographic proof', hasProof);
  if (!hasProof) {
    return { status: 'unsigned', checks, issuerName: issuer?.name, title, subjectName: subject };
  }

  const pub = issuer ? issuerPubKeyById[issuer.id] : undefined;
  const issuerTrusted = !!pub;
  push('Issuer is in the trusted registry', issuerTrusted, issuer?.name);

  const body = { ...raw };
  delete body.proof;
  const sigValid = issuerTrusted && edVerify(body, signature, pub);
  push('Ed25519 signature is valid (content untampered)', sigValid);

  const expiry = extractExpiry(raw);
  const expired = !!expiry && expiry.getTime() < Date.now();
  push('Within validity period', !expired, expiry ? expiry.toISOString() : 'no expiry');

  const revoked = revokedIds.has(raw.id) || raw.revoked === true;
  push('Not revoked', !revoked);

  let status = 'verified';
  if (!issuerTrusted) status = 'untrustedIssuer';
  else if (!sigValid) status = 'tampered';
  else if (revoked) status = 'revoked';
  else if (expired) status = 'expired';

  return { status, checks, issuerName: issuer?.name, title, subjectName: subject };
}
