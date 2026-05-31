// Seeds the trusted-issuer registry into the active store (idempotent).
import { ISSUERS } from './issuers.js';
import { publicKeyBase64 } from './crypto.js';

export async function seedIssuers(store) {
  for (const issuer of ISSUERS) {
    await store.issuers.upsert({
      id: issuer.id,
      name: issuer.name,
      description: issuer.description,
      publicKeyBase64: publicKeyBase64(issuer.seedPhrase),
      // NOTE: seedPhrase (private signing material) is intentionally NOT stored.
    });
  }
  return (await store.issuers.all()).length;
}

// Allow running directly: `npm run seed`
if (import.meta.url === `file://${process.argv[1]}`) {
  const { createStore } = await import('./store.js');
  const store = await createStore();
  const n = await seedIssuers(store);
  console.log(`Seeded issuer registry — ${n} issuers (${store.backend}).`);
  process.exit(0);
}
