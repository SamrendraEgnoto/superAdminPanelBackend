import express from 'express';
import morgan from 'morgan';
import helmet from 'helmet';
import cors from 'cors';
import path from 'path';
import { fileURLToPath } from 'url';
import errorHandler from './middlewares/errorHandler.js';
import authRoutes from './routes/authRoutes.js';
import superAdminRoutes from './routes/superAdminRoutes.js';
import adminRoutes from './routes/adminRoutes.js';
import userRoutes from './routes/userRoutes.js';
import buildingRoutes from './routes/buildingRoutes.js';
import bridgeRoutes from "./routes/bridgeRoutes.js";
import customerRightsRoutes from './routes/customerRights.js';
import reportRoutes from "./routes/reportRoutes.js";
import settingsRoutes from "./routes/settingsRoutes.js";
import internalRoutes from "./routes/internalRouter.js";
import notificationRoutes from "./routes/notificationRoutes.js";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const app = express();

// ===== MIDDLEWARE =====
app.use(cors({
  origin: (origin, callback) => {
    // Allow requests from any origin (DSA websites, 3D estimator domains, localhost) or non-browser (null/undefined)
    callback(null, true);
  },
  credentials: true,
  methods: ["GET", "POST", "PUT", "DELETE", "OPTIONS"],
  allowedHeaders: ["Content-Type", "Authorization", "X-Embed-Key", "X-Tenant-Key", "X-Tenant-Passkey", "x-tenant-passkey", "X-API-Key", "X-Requested-With"]
}));

app.use(morgan('dev'));
app.use(helmet({
  crossOriginResourcePolicy: { policy: "cross-origin" },
  crossOriginEmbedderPolicy: false
}));

app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// Serve static files
app.use('/uploads', express.static(path.join(__dirname, '../uploads')));

// ===== ROUTES =====
app.use('/api/auth', authRoutes);
app.use('/api/superadmin', superAdminRoutes);
app.use('/api/admin', adminRoutes);
app.use('/api/users', userRoutes);
app.use('/api/buildings', buildingRoutes);
app.use('/api/reports', reportRoutes);
app.use('/api/settings', settingsRoutes);
app.use('/api/bridge', bridgeRoutes);
app.use('/api/notifications', notificationRoutes);

// Public customer-rights router (token-based, no admin JWT)
app.use('/api/customer', customerRightsRoutes);

// INTERNAL SERVICE API — service-to-service only. Shared-secret guarded, and in
// production blocked at the network layer (localhost / internal network only).
app.use('/api/internal', internalRoutes);

// Root route
app.get('/', (req, res) => {
  res.json({
    message: 'Super Admin Panel API is running!',
    status: 'OK',
    timestamp: new Date()
  });
});

// Health check
app.get('/api/health', (req, res) => {
  res.json({ status: 'OK', timestamp: new Date() });
});

// Error handler (must be last)
app.use(errorHandler);

export default app;
