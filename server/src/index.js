import express from 'express';
import helmet from 'helmet';
import cors from 'cors';
import rateLimit from 'express-rate-limit';
import dotenv from 'dotenv';

import { createStore } from './store.js';
import { seedIssuers } from './seed.js';
import {
  ISSUERS,
  CATALOG,
  issueCredential,
  issuerById,
  credentialsForIdentity,
} from './issuers.js';
import { verifyCredential } from './verify.js';

dotenv.config();

const app = express();
const PORT = process.env.PORT || 4000;
const ADMIN_KEY = process.env.ADMIN_API_KEY || 'ndear-dev-admin-key';

let store;
let issuerPubKeyById = {};

// --- security middleware ---------------------------------------------------
app.use(helmet());
app.use(cors());
app.use(express.json({ limit: '256kb' }));
app.use(
  rateLimit({
    windowMs: 60 * 1000,
    limit: 120, // 120 req/min/IP
    standardHeaders: true,
    legacyHeaders: false,
  })
);

function requireAdmin(req, res, next) {
  if (req.get('x-api-key') !== ADMIN_KEY) {
    return res.status(401).json({ error: 'unauthorized' });
  }
  next();
}

// --- routes ----------------------------------------------------------------

app.get('/health', (_req, res) =>
  res.json({
    status: 'ok',
    service: 'ndear-wallet-api',
    storage: store?.backend ?? 'starting',
    issuers: ISSUERS.length,
  })
);

// Trusted-issuer registry (the wallet uses this to verify locally).
app.get('/api/issuers', async (_req, res) => {
  res.json(await store.issuers.all());
});

// Available credentials a learner can claim from connected platforms.
app.get('/api/catalog', (_req, res) => {
  res.json(
    CATALOG.map((c, i) => ({ index: i, ...c, issuerName: issuerById(c.issuerId)?.name }))
  );
});

// Issue (mint + sign) a credential — the "educational platform integration".
app.post('/api/issue', async (req, res) => {
  const { catalogIndex, subjectName } = req.body || {};
  if (
    !Number.isInteger(catalogIndex) ||
    catalogIndex < 0 ||
    catalogIndex >= CATALOG.length ||
    typeof subjectName !== 'string' ||
    !subjectName.trim()
  ) {
    return res.status(400).json({ error: 'invalid catalogIndex or subjectName' });
  }
  const issued = issueCredential(CATALOG[catalogIndex], subjectName.trim());
  await store.credentials.upsert({
    id: issued.id,
    format: issued.format,
    subjectName: subjectName.trim(),
    raw: issued.raw,
    documentHash: issued.documentHash,
    issuedAt: new Date(),
  });
  res.json(issued.raw);
});

// Fetch ALL of a learner's certificates from connected platforms by identity.
app.post('/api/learner/credentials', async (req, res) => {
  const { name, dateOfBirth } = req.body || {};
  const dobOk = typeof dateOfBirth === 'string' &&
      /^\d{4}-\d{2}-\d{2}$/.test(dateOfBirth);
  if (typeof name !== 'string' || !name.trim() || !dobOk) {
    return res
        .status(400)
        .json({ error: 'name and dateOfBirth (YYYY-MM-DD) are required' });
  }
  const issued = credentialsForIdentity(name.trim(), dateOfBirth);
  // persist the issued records (idempotent on deterministic id)
  for (const c of issued) {
    await store.credentials.upsert({
      id: c.id,
      format: c.format,
      subjectName: name.trim(),
      dateOfBirth,
      raw: c.raw,
      documentHash: c.documentHash,
      issuedAt: new Date(),
    });
  }
  res.json({
    name: name.trim(),
    dateOfBirth,
    count: issued.length,
    credentials: issued.map((c) => ({
      id: c.id,
      format: c.format,
      issuerName: c.issuerName,
      credential: c.raw,
    })),
  });
});

// THE VERIFICATION API — institutions POST a credential, get a verdict.
app.post('/api/verify', async (req, res) => {
  const raw = req.body?.credential ?? req.body;
  if (!raw || typeof raw !== 'object' || Array.isArray(raw)) {
    return res.status(400).json({ error: 'missing credential' });
  }
  const revoked = new Set((await store.revocations.all()).map((r) => r.id));
  const result = verifyCredential(raw, issuerPubKeyById, revoked);

  await store.logs.insert({
    at: new Date(),
    credentialId: raw.id || null,
    issuer: result.issuerName || null,
    status: result.status,
    valid: result.status === 'verified',
    ip: req.ip,
  });

  res.json(result);
});

// Revoke a credential (issuer/admin only).
app.post('/api/revoke', requireAdmin, async (req, res) => {
  const { id, reason } = req.body || {};
  if (typeof id !== 'string' || !id) {
    return res.status(400).json({ error: 'missing credential id' });
  }
  await store.revocations.upsert({
    id,
    reason: reason || 'unspecified',
    revokedAt: new Date(),
  });
  res.json({ id, revoked: true });
});

// Verification accuracy stats for the KPI dashboard.
app.get('/api/verify/stats', async (_req, res) => {
  const s = await store.logs.stats();
  res.json({
    totalVerifications: s.total,
    validVerifications: s.valid,
    accuracyPercent: s.total === 0 ? 100 : Number(((s.valid / s.total) * 100).toFixed(2)),
    byStatus: s.byStatus,
  });
});

app.use((err, _req, res, _next) => {
  console.error(err);
  res.status(500).json({ error: 'internal error' });
});

// --- boot ------------------------------------------------------------------
async function start() {
  store = await createStore();
  const n = await seedIssuers(store);
  issuerPubKeyById = Object.fromEntries(
    (await store.issuers.all()).map((d) => [d.id, d.publicKeyBase64])
  );
  app.listen(PORT, () => {
    console.log(
      `NDEAR Wallet API on :${PORT} — storage=${store.backend}, registry=${n} issuers`
    );
  });
}

start().catch((e) => {
  console.error('Failed to start server:', e.message);
  process.exit(1);
});
