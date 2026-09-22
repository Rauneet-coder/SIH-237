const mongoose = require('mongoose');
const env = require('./env');

/**
 * Connect to MongoDB using Mongoose
 * @param {string} [uri] - Optional custom connection string (used in testing)
 */
async function connectDB(uri = env.MONGODB_URI) {
  try {
    const conn = await mongoose.connect(uri);
    console.log(`[Database] MongoDB Connected: ${conn.connection.host}/${conn.connection.name}`);
    return conn;
  } catch (error) {
    console.error(`[Database Error] Connection failed: ${error.message}`);
    if (process.env.NODE_ENV !== 'test') {
      process.exit(1);
    }
    throw error;
  }
}

/**
 * Disconnect from MongoDB
 */
async function disconnectDB() {
  await mongoose.disconnect();
}

module.exports = {
  connectDB,
  disconnectDB
};
