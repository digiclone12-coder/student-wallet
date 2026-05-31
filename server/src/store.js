// Persistence abstraction with two interchangeable backends:
//   * MongoDB (used whenever the Atlas URI is reachable)
//   * in-memory (automatic fallback so the API still runs where Mongo egress
//     is blocked, e.g. networks that intercept the 27017 TLS handshake)
//
// The route layer only depends on this small interface, never on the driver.
import { MongoClient } from 'mongodb';
import dotenv from 'dotenv';

dotenv.config();

function mongoStore(db) {
  const issuers = db.collection('issuers');
  const credentials = db.collection('credentials');
  const revocations = db.collection('revocations');
  const logs = db.collection('verification_logs');
  return {
    backend: 'mongodb',
    issuers: {
      all: () => issuers.find({}, { projection: { _id: 0 } }).toArray(),
      upsert: (doc) => issuers.updateOne({ id: doc.id }, { $set: doc }, { upsert: true }),
    },
    credentials: {
      upsert: (doc) =>
        credentials.updateOne({ id: doc.id }, { $set: doc }, { upsert: true }),
    },
    revocations: {
      all: () => revocations.find({}, { projection: { _id: 0 } }).toArray(),
      upsert: (doc) =>
        revocations.updateOne({ id: doc.id }, { $set: doc }, { upsert: true }),
    },
    logs: {
      insert: (doc) => logs.insertOne(doc),
      stats: async () => {
        const total = await logs.countDocuments();
        const valid = await logs.countDocuments({ valid: true });
        const grouped = await logs
          .aggregate([{ $group: { _id: '$status', count: { $sum: 1 } } }])
          .toArray();
        return {
          total,
          valid,
          byStatus: Object.fromEntries(grouped.map((g) => [g._id, g.count])),
        };
      },
    },
  };
}

function memoryStore() {
  const issuers = new Map();
  const credentials = new Map();
  const revocations = new Map();
  const logs = [];
  return {
    backend: 'memory',
    issuers: {
      all: async () => [...issuers.values()],
      upsert: async (doc) => void issuers.set(doc.id, doc),
    },
    credentials: {
      upsert: async (doc) => void credentials.set(doc.id, doc),
    },
    revocations: {
      all: async () => [...revocations.values()],
      upsert: async (doc) => void revocations.set(doc.id, doc),
    },
    logs: {
      insert: async (doc) => void logs.push(doc),
      stats: async () => {
        const byStatus = {};
        let valid = 0;
        for (const l of logs) {
          byStatus[l.status] = (byStatus[l.status] || 0) + 1;
          if (l.valid) valid++;
        }
        return { total: logs.length, valid, byStatus };
      },
    },
  };
}

/** Connect to Mongo, or fall back to in-memory with a clear warning. */
export async function createStore() {
  const uri = process.env.MONGODB_URI;
  const dbName = process.env.DB_NAME || 'ndear_wallet';
  if (!uri) {
    console.warn('[store] MONGODB_URI not set — using in-memory store.');
    return memoryStore();
  }
  try {
    const client = new MongoClient(uri, { serverSelectionTimeoutMS: 8000 });
    await client.connect();
    const db = client.db(dbName);
    await db.collection('issuers').createIndex({ id: 1 }, { unique: true });
    await db.collection('credentials').createIndex({ id: 1 }, { unique: true });
    await db.collection('revocations').createIndex({ id: 1 }, { unique: true });
    await db.collection('verification_logs').createIndex({ at: -1 });
    console.log(`[store] Connected to MongoDB (${dbName}).`);
    return mongoStore(db);
  } catch (e) {
    console.warn(
      `[store] MongoDB unreachable (${e.message}). Falling back to in-memory store.`
    );
    return memoryStore();
  }
}
