import 'dotenv/config';
import connectDB from '../config/db.mjs';
import SuperAdmin from '../models/SuperAdmin.js';

async function run() {
  await connectDB();
  const email = 'karishma.s@egnoto.com';
  const password = 'egnotokarishma';
  const exists = await SuperAdmin.findOne({ email: email.toLowerCase() });
  if (exists) {
    console.log('Super admin already exists');
    process.exit(0);
  }
  const sa = new SuperAdmin({ firstName: 'Karishma', lastName: 'S', email, password, role: 'root', createdBy: null, isEmailVerified: true });
  await sa.save();
  console.log('Super admin created');
  process.exit(0);
}

run().catch(err => {
  console.error(err);
  process.exit(1);
});
