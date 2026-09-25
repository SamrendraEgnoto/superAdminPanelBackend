import mongoose from 'mongoose';
import bcrypt from 'bcryptjs';

async function createRootAdmin() {
  try {
    await mongoose.connect(
      'mongodb+srv://egnotodevteam_db_user:aCK6dZ56v9f3UFZm@cluster0.23272wr.mongodb.net/?appName=Cluster0'
    );

    console.log('MongoDB connected');

    const password = 'Samrendra@#1234';
    const hashedPassword = await bcrypt.hash(password, 10);

    const SuperAdmin = mongoose.model('SuperAdmin');

    const sa = new SuperAdmin({
      firstName: 'Samrendra',
      lastName: 'Egnoto',
      email: 'samrendra.v@egnoto.com',
      password: hashedPassword,
      role: 'root',
      isEmailVerified: true,
      createdBy: null
    });

    await sa.save();

    console.log('Root Super Admin created successfully');
    console.log('Email: samrendra.v@egnoto.com');
    console.log('Password: Samrendra@#1234');
    console.log('Role: root');

    await mongoose.disconnect();
  } catch (err) {
    console.error('Error:', err);

    try {
      await mongoose.disconnect();
    } catch {}

    process.exit(1);
  }
}

createRootAdmin();