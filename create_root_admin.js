import mongoose from 'mongoose';
import bcrypt from 'bcryptjs';
import dotenv from 'dotenv';
import './src/models/SuperAdmin.js';
import './src/models/Admin.js';
import './src/models/User.js';

dotenv.config();

mongoose.connect(process.env.MONGO_URI, {
  useNewUrlParser: true,
  useUnifiedTopology: true
}).then(() => console.log('MongoDB connected')).catch(err => {
  console.error('MongoDB connection error:', err.message);
  process.exit(1);
});

const SuperAdmin = mongoose.model('SuperAdmin');

const createRootAdmin = async () => {
  const { firstName, lastName, email, password } = {
    firstName: 'Samrendra',
    lastName: 'Egnoto',
    email: 'samrendra.v@egnoto.com',
    password: 'Samrendra@#1234'
  };

  // Check if root already exists
  const existing = await SuperAdmin.findOne({ email: email.toLowerCase(), role: 'root' });
  if (existing) {
    console.log('Root Super Admin already exists');
    process.exit(0);
  }

  const hashedPassword = await bcrypt.hash(password, 10);

  const sa = new SuperAdmin({
    firstName,
    lastName,
    email: email.toLowerCase(),
    password: hashedPassword,
    role: 'root',
    isEmailVerified: true,
    createdBy: null
  });

  await sa.save();
  console.log('Root Super Admin created successfully');
  console.log('Email:', sa.email);
  console.log('Password: Samrendra@#1234');
  console.log('Role: root');
  
  process.exit(0);
};

createRootAdmin();
