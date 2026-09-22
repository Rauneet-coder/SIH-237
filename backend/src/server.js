const express = require('express');
const cors = require('cors');
const env = require('./config/env');
const { connectDB } = require('./config/db');
const errorHandler = require('./middleware/errorHandler');

const authRoutes = require('./routes/authRoutes');
const documentRoutes = require('./routes/documentRoutes');
const provenanceRoutes = require('./routes/provenanceRoutes');

const app = express();

// Global Middleware
app.use(
  cors({
    origin: env.CORS_ORIGIN,
    credentials: true
  })
);
app.use(express.json({ limit: '50mb' }));
app.use(express.urlencoded({ extended: true, limit: '50mb' }));

// Health Check Endpoint
app.get('/health', (req, res) => {
  res.json({
    status: 'ok',
    service: 'SIH26237-Provenance-System',
    runtime: 'Node.js',
    nodeVersion: process.version,
    version: '1.0.0',
    timestamp: new Date().toISOString()
  });
});

// Mount Routes
app.use('/api/auth', authRoutes);
app.use('/api/documents', documentRoutes);
app.use('/api/provenance', provenanceRoutes);

// Centralized Error Handling
app.use(errorHandler);

// Start server if executed directly
if (require.main === module) {
  (async () => {
    try {
      await connectDB();
      app.listen(env.PORT, () => {
        console.log(`[Server] SIH26237 Backend running on port ${env.PORT}`);
        console.log(`[Server] Health check: http://localhost:${env.PORT}/health`);
        console.log(`[Server] Provenance verification: http://localhost:${env.PORT}/api/provenance/verify`);
      });
    } catch (err) {
      console.error('[Server Error] Failed to start server:', err.message);
      process.exit(1);
    }
  })();
}

module.exports = app;
