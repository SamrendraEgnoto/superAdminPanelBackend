const path = require('path');
require('dotenv').config({ path: path.join(__dirname, '.env') });

module.exports = {
  apps: [
    {
      name: "super-admin-panel",
      script: "src/server.js",
      cwd: __dirname,
      instances: 1,
      autorestart: true,
      watch: false,
      max_memory_restart: "200M",
      env: {
        NODE_ENV: "development",
        PORT: 5001,
        MONGO_URI: "mongodb+srv://egnotodevteam_db_user:aCK6dZ56v9f3UFZm@cluster0.23272wr.mongodb.net/Estimator_Manager?retryWrites=true&w=majority",
        SECONDARY_MONGO_URI: process.env.SECONDARY_MONGO_URI || "mongodb+srv://egnotodevteam_db_user:aCK6dZ56v9f3UFZm@cluster0.23272wr.mongodb.net/Estimator_Manager?retryWrites=true&w=majority",
        SECOUNDARY_MONGO_URI: process.env.SECOUNDARY_MONGO_URI || "mongodb+srv://egnotodevteam_db_user:aCK6dZ56v9f3UFZm@cluster0.23272wr.mongodb.net/Estimator_Manager?retryWrites=true&w=majority",
        JWT_SECRET: process.env.JWT_SECRET || "Egnoto@123",
        SUPERADMIN_EMAIL: process.env.SUPERADMIN_EMAIL || "karishma.s@egnoto.com",
        SUPERADMIN_PASSWORD: process.env.SUPERADMIN_PASSWORD || "egnotokarishma",
        EMAIL_HOST: process.env.EMAIL_HOST || "smtp.gmail.com",
        EMAIL_PORT: process.env.EMAIL_PORT || "587",
        EMAIL_USER: process.env.EMAIL_USER || "egnotodevteam@gmail.com",
        EMAIL_PASS: process.env.EMAIL_PASS || "lrbocdhirpziomws",
        ENCRYPTION_MASTER_KEY: process.env.ENCRYPTION_MASTER_KEY || "1c8fd6b5217a88ff8e6f3867fa724ef647ad643a06ed6191e0612c497318aebd",
        VAULT_ADDR: process.env.VAULT_ADDR || "http://127.0.0.1:8200",
        VAULT_ROLE_ID: process.env.VAULT_ROLE_ID || "d5acf7da-8685-3742-b82c-84cfed83206c",
        VAULT_SECRET_ID: process.env.VAULT_SECRET_ID || "b41deb5a-5310-4f15-0e81-a894baf31092",
        VAULT_TRANSIT_KEY: process.env.VAULT_TRANSIT_KEY || "tenant-master-key",
        VAULT_TOKEN: process.env.VAULT_TOKEN || "",
        VAULT_SKIP_VERIFY: process.env.VAULT_SKIP_VERIFY || "true",
        KMS_MODE: process.env.KMS_MODE || "vault",
        ESTIMATOR_NODE_URL: process.env.ESTIMATOR_NODE_URL || "http://localhost:5568",
        ESTIMATOR_BASE_URL: process.env.ESTIMATOR_BASE_URL || "https://gripestimator.com/estimator-ai",
        BRIDGE_API_KEY: "bridge-shared-key-secret",
        INTERNAL_SERVICE_SECRET: "c1b3f7a9e2d4c6f8a0b1d2e3f4a5b6c7d8e9f0a1b2c3d4e5f6a7b8c9d0e1f2a3"
      },
      env_production: {
        NODE_ENV: "production",
        PORT: process.env.PORT || 5001,
        MONGO_URI: process.env.MONGO_URI || "mongodb+srv://egnotodevteam_db_user:aCK6dZ56v9f3UFZm@cluster0.23272wr.mongodb.net/Estimator_Manager?retryWrites=true&w=majority",
        ESTIMATOR_BASE_URL: process.env.ESTIMATOR_BASE_URL || "https://gripestimator.com/estimator-ai",
        INTERNAL_SERVICE_SECRET: "c1b3f7a9e2d4c6f8a0b1d2e3f4a5b6c7d8e9f0a1b2c3d4e5f6a7b8c9d0e1f2a3"
      }
    }
  ]
};
