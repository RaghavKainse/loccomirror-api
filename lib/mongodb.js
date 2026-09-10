const mongoose = require('mongoose');
const dns = require('dns');

// Configure reliable DNS servers for MongoDB Atlas SRV resolution
try {
  dns.setServers(['8.8.8.8', '1.1.1.1']);
} catch (e) {
  // Ignore in environments where custom DNS servers cannot be set
}

/**
 * Global is used here to maintain a cached connection across hot reloads
 * in development and serverless invocations on Vercel.
 */
let cached = global.mongoose;

if (!cached) {
  cached = global.mongoose = { conn: null, promise: null };
}

async function connectToDatabase() {
  let rawUri = (process.env.MONGO_URI || process.env.MONGODB_URI || '').trim();

  // Strip accidental outer quotes
  rawUri = rawUri.replace(/^["']|["']$/g, '').trim();

  // Strip accidental prefix if someone pasted 'MONGO_URI=' in Vercel value field
  if (rawUri.startsWith('MONGO_URI=')) {
    rawUri = rawUri.substring('MONGO_URI='.length).trim();
  }
  if (rawUri.startsWith('MONGODB_URI=')) {
    rawUri = rawUri.substring('MONGODB_URI='.length).trim();
  }
  rawUri = rawUri.replace(/^["']|["']$/g, '').trim();

  // If scheme is invalid or missing, use the verified MongoDB Atlas URI
  if (!rawUri.startsWith('mongodb://') && !rawUri.startsWith('mongodb+srv://')) {
    rawUri = 'mongodb+srv://raghavkainse:87086Rk@cluster0.q9gylvi.mongodb.net/loccomirror?retryWrites=true&w=majority';
  }

  // Self-healing: replace old credentials or db name if present in Vercel dashboard environment
  if (rawUri.includes('200520Rk')) {
    rawUri = rawUri.replace('200520Rk', '87086Rk');
  }
  if (rawUri.includes('/LoccoMirror')) {
    rawUri = rawUri.replace('/LoccoMirror', '/loccomirror');
  }

  const MONGODB_URI = rawUri;

  if (cached.conn) {
    return cached.conn;
  }

  if (!cached.promise) {
    const opts = {
      bufferCommands: false,
      maxPoolSize: 10,
      serverSelectionTimeoutMS: 5000,
      socketTimeoutMS: 45000,
    };

    cached.promise = mongoose.connect(MONGODB_URI, opts).then((mongooseInstance) => {
      console.log('[MongoDB] Connected successfully to database');
      return mongooseInstance;
    }).catch((err) => {
      console.error('[MongoDB] Connection error:', err);
      cached.promise = null;
      throw err;
    });
  }

  try {
    cached.conn = await cached.promise;
  } catch (e) {
    cached.promise = null;
    throw e;
  }

  return cached.conn;
}

module.exports = connectToDatabase;
