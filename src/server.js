import 'dotenv/config';

import app from './app.js';
import connectDB from './config/db.mjs';
import './utils/backupService.js';
import { initializeVault } from './utils/kmsClient.js';

const PORT = process.env.PORT || 5001;

const startServer = async () => {
  try {
    await connectDB();
    // Authenticate against Vault at startup (non-blocking; auto-retries lazily
    // on first KMS use if Vault is temporarily unavailable).
    initializeVault();
    app.listen(PORT, () => {
      console.log(`Server running on port ${PORT}`);
    });
  } catch (err) {
    console.error('Failed to start server:', err);
    process.exit(1);
  }
};

startServer();
