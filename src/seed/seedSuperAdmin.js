import 'dotenv/config';
import connectDB from '../config/db.mjs';
import SuperAdmin from '../models/SuperAdmin.js';

async function seed() {
  await connectDB();
  const email = process.env.SUPERADMIN_EMAIL;
  const password = process.env.SUPERADMIN_PASSWORD;
  if (!email || !password) {
    console.error('Please set SUPERADMIN_EMAIL and SUPERADMIN_PASSWORD in .env');
    process.exit(1);
  }
  // Exactly one root SuperAdmin should exist; enforce at seed time
  const rootExists = await SuperAdmin.findOne({ email: email.toLowerCase(), role: 'root' });
  if (rootExists) {
    console.log('Root Super Admin already exists');
    process.exit(0);
  }
  // Create the root SuperAdmin with role='root' and createdBy=null
  const sa = new SuperAdmin({ firstName: 'Super', lastName: 'Admin', email, password, role: 'root', isEmailVerified: true });
  await sa.save();
  console.log('Root Super Admin seeded');
  process.exit(0);
}

seed().catch(err => {
  console.error(err);
  process.exit(1);
});
