// Trusted issuers (educational platforms) and the credential factory.
// Seeds match the Flutter app's IssuerRegistry so public keys are identical.
import { randomUUID } from 'crypto';
import { sign, sha256Hex, canonicalize } from './crypto.js';

/** Normalised identity key from name + date of birth. */
export function identityKey(name, dob) {
  return sha256Hex(`${String(name).trim().toLowerCase()}|${String(dob).trim()}`);
}

/** Deterministic UUID derived from a seed, so re-fetches are idempotent. */
function deterministicUuid(seed) {
  const h = sha256Hex(seed);
  return `${h.slice(0, 8)}-${h.slice(8, 12)}-${h.slice(12, 16)}-${h.slice(16, 20)}-${h.slice(20, 32)}`;
}

export const ISSUERS = [
  {
    id: 'did:ndear:swayam',
    name: 'SWAYAM',
    description: 'Ministry of Education — national MOOC platform',
    seedPhrase: 'ndear-issuer-seed::swayam::v1',
  },
  {
    id: 'did:ndear:nptel',
    name: 'NPTEL',
    description: 'National Programme on Technology Enhanced Learning (IITs/IISc)',
    seedPhrase: 'ndear-issuer-seed::nptel::v1',
  },
  {
    id: 'did:ndear:diksha',
    name: 'DIKSHA',
    description: 'National platform for school education',
    seedPhrase: 'ndear-issuer-seed::diksha::v1',
  },
  {
    id: 'did:ndear:nsdc',
    name: 'NSDC',
    description: 'National Skill Development Corporation',
    seedPhrase: 'ndear-issuer-seed::nsdc::v1',
  },
];

export const CATALOG = [
  {
    issuerId: 'did:ndear:swayam',
    format: 'w3c-vc',
    title: 'Introduction to Python Programming',
    competencies: ['python', 'programming-basics'],
    pathwayId: 'data-science',
    creditPoints: 4,
    claims: { Grade: 'A', Score: '88%', Duration: '8 weeks' },
  },
  {
    issuerId: 'did:ndear:nptel',
    format: 'ob3',
    title: 'Data Structures & Algorithms',
    competencies: ['dsa', 'problem-solving', 'programming-basics'],
    pathwayId: 'data-science',
    creditPoints: 6,
    claims: { Grade: 'Elite + Gold', Score: '92%', Duration: '12 weeks' },
  },
  {
    issuerId: 'did:ndear:nptel',
    format: 'ndear-mc',
    title: 'Machine Learning Foundations',
    competencies: ['machine-learning', 'statistics'],
    pathwayId: 'data-science',
    creditPoints: 6,
    claims: { Level: 'Intermediate', Score: '85%', Duration: '10 weeks' },
  },
  {
    issuerId: 'did:ndear:diksha',
    format: 'xapi',
    title: 'Digital Pedagogy for Educators',
    competencies: ['pedagogy', 'digital-literacy'],
    pathwayId: 'educator',
    creditPoints: 3,
    claims: { Result: 'Completed', Modules: '6/6' },
  },
  {
    issuerId: 'did:ndear:nsdc',
    format: 'json-cert',
    title: 'Certified Front-End Developer',
    competencies: ['html-css', 'javascript', 'programming-basics'],
    pathwayId: 'web-dev',
    creditPoints: 5,
    claims: { 'Job Role': 'Web Developer', 'NSQF Level': '5' },
  },
  {
    issuerId: 'did:ndear:swayam',
    format: 'pdf-ref',
    title: 'Diploma in Cyber Security',
    competencies: ['security', 'networking'],
    pathwayId: 'security',
    creditPoints: 8,
    claims: { Type: 'PDF transcript', Pages: '4' },
  },
];

export function issuerById(id) {
  return ISSUERS.find((i) => i.id === id);
}

/**
 * Builds and signs a credential document.
 * @param spec     catalog entry
 * @param subject  either a name string, or { name, dob, idSeed }.
 *                 When idSeed is given the credential id is deterministic
 *                 (so the same learner re-fetching gets the same credential).
 */
export function issueCredential(spec, subject) {
  const issuer = issuerById(spec.issuerId);
  if (!issuer) throw new Error('unknown issuer');

  const norm = typeof subject === 'string' ? { name: subject } : (subject || {});
  const subjectName = norm.name;
  const dob = norm.dob || null;
  const id = norm.idSeed
    ? 'urn:uuid:' + deterministicUuid(norm.idSeed)
    : 'urn:uuid:' + randomUUID();
  const now = new Date().toISOString();
  const expiry =
    spec.format === 'ndear-mc'
      ? new Date(Date.now() + 1000 * 60 * 60 * 24 * 365 * 3).toISOString()
      : null;

  let body;
  if (spec.format === 'pdf-ref') {
    body = {
      format: 'pdf-ref',
      id,
      title: spec.title,
      issuer: { id: issuer.id, name: issuer.name },
      recipient: subjectName,
      ...(dob ? { recipientDateOfBirth: dob } : {}),
      issued: now,
      documentUrl: `https://docs.ndear.gov.in/${id.split(':').pop()}.pdf`,
      claims: spec.claims,
    };
  } else if (spec.format === 'xapi') {
    body = {
      format: 'xapi',
      id,
      actor: { name: subjectName, ...(dob ? { dateOfBirth: dob } : {}), objectType: 'Agent' },
      verb: { id: 'http://adlnet.gov/expapi/verbs/completed' },
      object: {
        id: `https://diksha.gov.in/course/${id.split(':').pop()}`,
        definition: { name: { 'en-IN': spec.title } },
      },
      result: spec.claims,
      timestamp: now,
      issuer: { id: issuer.id, name: issuer.name },
      competencies: spec.competencies,
      creditPoints: spec.creditPoints,
      pathwayId: spec.pathwayId,
    };
  } else {
    const type =
      spec.format === 'ob3'
        ? ['VerifiableCredential', 'OpenBadgeCredential']
        : spec.format === 'ndear-mc'
          ? ['VerifiableCredential', 'NdearMicroCredential']
          : ['VerifiableCredential'];
    body = {
      '@context': [
        'https://www.w3.org/ns/credentials/v2',
        ...(spec.format === 'ob3'
          ? ['https://purl.imsglobal.org/spec/ob/v3p0/context.json']
          : []),
      ],
      format: spec.format,
      id,
      type,
      issuer: { id: issuer.id, name: issuer.name },
      validFrom: now,
      ...(expiry ? { validUntil: expiry } : {}),
      credentialSubject: {
        name: subjectName,
        ...(dob ? { dateOfBirth: dob } : {}),
        achievement: {
          name: spec.title,
          competencies: spec.competencies,
          creditPoints: spec.creditPoints,
          pathwayId: spec.pathwayId,
          claims: spec.claims,
        },
      },
    };
  }

  const signature = sign(body, issuer.seedPhrase);
  const raw = {
    ...body,
    proof: {
      type: 'Ed25519Signature2020',
      created: now,
      verificationMethod: `${issuer.id}#key-1`,
      proofPurpose: 'assertionMethod',
      proofValue: signature,
    },
  };

  const documentHash =
    spec.format === 'pdf-ref' ? sha256Hex(canonicalize(body)) : null;

  return { id, format: spec.format, raw, documentHash };
}

// ---------------------------------------------------------------------------
// Identity-based credential lookup (fetch a learner's certificates by
// name + date of birth, the way a real platform federation would).
// ---------------------------------------------------------------------------

// Pre-registered demo learners → the catalog indices each has earned.
// (name is matched case-insensitively; dob is ISO yyyy-mm-dd)
export const LEARNER_RECORDS = [
  { name: 'Asha Rao', dob: '2002-04-15', catalog: [0, 1, 2] },
  { name: 'Ravi Kumar', dob: '2000-11-30', catalog: [4, 5] },
  { name: 'Meena Iyer', dob: '1999-07-08', catalog: [0, 3, 4, 5] },
];

/**
 * Returns the signed credentials a learner holds across all connected
 * platforms, identified by name + date of birth.
 *
 * If the identity isn't pre-registered, a stable personalised set is derived
 * deterministically from the identity hash so every learner gets a meaningful,
 * reproducible result (a real deployment would instead query each platform's
 * records API). Credential ids are deterministic → idempotent re-fetches.
 */
export function credentialsForIdentity(name, dob) {
  const key = identityKey(name, dob);
  const match = LEARNER_RECORDS.find(
    (r) => r.name.toLowerCase() === String(name).trim().toLowerCase() && r.dob === dob
  );

  let indices;
  if (match) {
    indices = match.catalog;
  } else {
    // Deterministic personalised selection: 2–4 credentials chosen by hash.
    const h = parseInt(key.slice(0, 8), 16);
    const count = 2 + (h % 3); // 2..4
    const start = h % CATALOG.length;
    indices = Array.from({ length: count }, (_, i) => (start + i) % CATALOG.length);
    indices = [...new Set(indices)];
  }

  return indices.map((i) => {
    const issued = issueCredential(CATALOG[i], {
      name: String(name).trim(),
      dob,
      idSeed: `${key}|${i}`,
    });
    return { ...issued, issuerName: issuerById(CATALOG[i].issuerId)?.name };
  });
}
