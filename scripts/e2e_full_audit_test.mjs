import mongoose from 'mongoose';
import dotenv from 'dotenv';
import path from 'path';

dotenv.config({ path: path.join(process.cwd(), '.env') });

const BASE_URL = process.env.API_URL || 'http://localhost:5001';
const TS = Date.now();

console.log(`=======================================================`);
console.log(`🚀 STARTING END-TO-END AUTOMATED TEST SUITE`);
console.log(`   Base URL: ${BASE_URL}`);
console.log(`   Timestamp Run: ${TS}`);
console.log(`=======================================================\n`);

const results = {
  passed: 0,
  failed: 0,
  details: []
};

function record(name, success, info = '') {
  if (success) {
    results.passed++;
    console.log(`  ✅ [PASS] ${name} ${info ? `(${info})` : ''}`);
    results.details.push({ name, status: 'PASS', info });
  } else {
    results.failed++;
    console.error(`  ❌ [FAIL] ${name} - ${info}`);
    results.details.push({ name, status: 'FAIL', info });
  }
}

async function api(endpoint, options = {}) {
  const url = `${BASE_URL}${endpoint}`;
  const res = await fetch(url, {
    headers: {
      'Content-Type': 'application/json',
      ...(options.token ? { Authorization: `Bearer ${options.token}` } : {}),
      ...options.headers
    },
    ...options
  });
  let body = null;
  try {
    body = await res.json();
  } catch (err) {
    body = null;
  }
  return { status: res.status, ok: res.ok, body };
}

async function run() {
  // --------------------------------------------------------------------------
  // STEP 1: LOGIN AS ROOT SUPER ADMIN (RSA)
  // --------------------------------------------------------------------------
  console.log(`\n--- STEP 1: RSA AUTHENTICATION ---`);
  const rsaEmail = process.env.SUPERADMIN_EMAIL || 'karishma.s@egnoto.com';
  const rsaPassword = process.env.SUPERADMIN_PASSWORD || 'egnotokarishma';

  const rsaLogin = await api('/api/auth/login', {
    method: 'POST',
    body: JSON.stringify({ email: rsaEmail, password: rsaPassword, role: 'root' })
  });

  if (!rsaLogin.ok || !rsaLogin.body?.token) {
    record('RSA Login', false, `Status ${rsaLogin.status}: ${JSON.stringify(rsaLogin.body)}`);
    throw new Error('Fatal: RSA login failed');
  }
  const rsaToken = rsaLogin.body.token;
  record('RSA Login', true, `Logged in as ${rsaEmail}`);

  // --------------------------------------------------------------------------
  // STEP 2: RSA CREATES 10 RCAs (Root Created Admins)
  // --------------------------------------------------------------------------
  console.log(`\n--- STEP 2: RSA CREATING 10 RCAs (Root Created Admins) ---`);
  const createdRcas = [];
  for (let i = 1; i <= 10; i++) {
    const email = `rca_${TS}_${i}@enterprisetest.com`;
    const password = `RcaPass@123${i}`;
    const companyName = `RCA Enterprise Corp ${TS} ${i}`;
    const phone = `+1 20255501${String(i).padStart(2, '0')}`;

    const res = await api('/api/superadmin/admins', {
      method: 'POST',
      token: rsaToken,
      body: JSON.stringify({
        firstName: `RootAdmin${i}`,
        lastName: `Test${i}`,
        email,
        password,
        companyName,
        phone,
        plan: 'Pro' // Pro has userLimit: 20
      })
    });

    if (res.status === 201 && res.body?.data) {
      createdRcas.push({ id: res.body.data._id || res.body.data.id, email, password, companyName });
      record(`Create RCA #${i}`, true, `Email: ${email}, Phone: ${phone}`);
    } else {
      record(`Create RCA #${i}`, false, `Status ${res.status}: ${JSON.stringify(res.body)}`);
    }
  }

  // --------------------------------------------------------------------------
  // STEP 3: RSA CREATES 10 DSAs (Delegated Super Admins)
  // --------------------------------------------------------------------------
  console.log(`\n--- STEP 3: RSA CREATING 10 DSAs (Delegated Super Admins) ---`);
  const createdDsas = [];
  for (let i = 1; i <= 10; i++) {
    const email = `dsa_${TS}_${i}@enterprisetest.com`;
    const password = `DsaPass@123${i}`;
    const phone = `+44 79111234${String(i).padStart(2, '0')}`;

    const res = await api('/api/superadmin/superadmins', {
      method: 'POST',
      token: rsaToken,
      body: JSON.stringify({
        firstName: `DelegatedSA${i}`,
        lastName: `Branch${i}`,
        email,
        password,
        department: 'Operations',
        phone,
        location: 'London'
      })
    });

    if (res.status === 201 && res.body?.data) {
      createdDsas.push({ id: res.body.data._id || res.body.data.id, email, password });
      record(`Create DSA #${i}`, true, `Email: ${email}, Phone: ${phone}`);
    } else {
      record(`Create DSA #${i}`, false, `Status ${res.status}: ${JSON.stringify(res.body)}`);
    }
  }

  // --------------------------------------------------------------------------
  // STEP 4: VERIFY LOGIN FOR RCA AND DSA ACCOUNTS
  // --------------------------------------------------------------------------
  console.log(`\n--- STEP 4: AUTHENTICATION FOR CREATED RCAs AND DSAs ---`);
  // Test login for all 10 RCAs
  for (let i = 0; i < createdRcas.length; i++) {
    const rca = createdRcas[i];
    const logRes = await api('/api/auth/login', {
      method: 'POST',
      body: JSON.stringify({ email: rca.email, password: rca.password, role: 'admin' })
    });
    if (logRes.ok && logRes.body?.token) {
      rca.token = logRes.body.token;
      record(`RCA #${i + 1} Login`, true, `Token received`);
    } else {
      record(`RCA #${i + 1} Login`, false, `Status ${logRes.status}: ${JSON.stringify(logRes.body)}`);
    }
  }

  // Test login for all 10 DSAs
  for (let i = 0; i < createdDsas.length; i++) {
    const dsa = createdDsas[i];
    const logRes = await api('/api/auth/login', {
      method: 'POST',
      body: JSON.stringify({ email: dsa.email, password: dsa.password, role: 'superadmin' })
    });
    if (logRes.ok && logRes.body?.token) {
      dsa.token = logRes.body.token;
      record(`DSA #${i + 1} Login`, true, `Token received`);
    } else {
      record(`DSA #${i + 1} Login`, false, `Status ${logRes.status}: ${JSON.stringify(logRes.body)}`);
    }
  }

  const primaryDsa = createdDsas[0];
  const primaryRca = createdRcas[0];

  if (!primaryDsa?.token || !primaryRca?.token) {
    throw new Error('Fatal: Primary DSA or Primary RCA failed to authenticate');
  }

  // --------------------------------------------------------------------------
  // STEP 5: DSA CREATES 10 ADAMS (DSA Created Admins / Data-Viewers)
  // --------------------------------------------------------------------------
  console.log(`\n--- STEP 5: DSA CREATING 10 ADAMS (DSA-Created Admins) ---`);
  const dsaAdmins = [];
  for (let i = 1; i <= 10; i++) {
    const email = `dsa_admin_${TS}_${i}@enterprisetest.com`;
    const password = `DsaAdmPass@123${i}`;
    const companyName = `DSA Sub Corp ${TS} ${i}`;
    const phone = `+91 98765432${String(i).padStart(2, '0')}`;

    const res = await api('/api/superadmin/admins', {
      method: 'POST',
      token: primaryDsa.token,
      body: JSON.stringify({
        firstName: `DsaSubAdmin${i}`,
        lastName: `Sub${i}`,
        email,
        password,
        companyName,
        phone
      })
    });

    if (res.status === 201 && res.body?.data) {
      dsaAdmins.push({ id: res.body.data._id || res.body.data.id, email, password, companyName });
      record(`DSA Created Admin #${i}`, true, `Email: ${email}`);
    } else {
      record(`DSA Created Admin #${i}`, false, `Status ${res.status}: ${JSON.stringify(res.body)}`);
    }
  }

  // Login as DSA-created Admins
  for (let i = 0; i < dsaAdmins.length; i++) {
    const adm = dsaAdmins[i];
    const logRes = await api('/api/auth/login', {
      method: 'POST',
      body: JSON.stringify({ email: adm.email, password: adm.password, role: 'admin' })
    });
    if (logRes.ok && logRes.body?.token) {
      adm.token = logRes.body.token;
      record(`DSA Admin #${i + 1} Login`, true);
    } else {
      record(`DSA Admin #${i + 1} Login`, false, `Status ${logRes.status}: ${JSON.stringify(logRes.body)}`);
    }
  }

  // --------------------------------------------------------------------------
  // STEP 6: DSA CREATES 10 USERS (DSA Created Users)
  // --------------------------------------------------------------------------
  console.log(`\n--- STEP 6: DSA CREATING 10 USERS (DSA-Created Users) ---`);
  const dsaUsers = [];
  for (let i = 1; i <= 10; i++) {
    const email = `dsa_user_${TS}_${i}@enterprisetest.com`;
    const password = `DsaUserPass@123${i}`;
    const phone = `+1 41555502${String(i).padStart(2, '0')}`;

    const res = await api('/api/superadmin/users', {
      method: 'POST',
      token: primaryDsa.token,
      body: JSON.stringify({
        firstName: `DsaUser${i}`,
        lastName: `Member${i}`,
        email,
        password,
        phone,
        role: 'user'
      })
    });

    if (res.status === 201 && res.body?.data) {
      dsaUsers.push({ id: res.body.data._id || res.body.data.id, email, password });
      record(`DSA Created User #${i}`, true, `Email: ${email}`);
    } else {
      record(`DSA Created User #${i}`, false, `Status ${res.status}: ${JSON.stringify(res.body)}`);
    }
  }

  // Login as DSA-created Users
  for (let i = 0; i < dsaUsers.length; i++) {
    const usr = dsaUsers[i];
    const logRes = await api('/api/auth/login', {
      method: 'POST',
      body: JSON.stringify({ email: usr.email, password: usr.password, role: 'user' })
    });
    if (logRes.ok && logRes.body?.token) {
      usr.token = logRes.body.token;
      record(`DSA User #${i + 1} Login`, true);
    } else {
      record(`DSA User #${i + 1} Login`, false, `Status ${logRes.status}: ${JSON.stringify(logRes.body)}`);
    }
  }

  // --------------------------------------------------------------------------
  // STEP 7: RCA CREATES 10 USERS (RCA Created Users)
  // --------------------------------------------------------------------------
  console.log(`\n--- STEP 7: RCA CREATING 10 USERS (RCA-Created Users) ---`);
  const rcaUsers = [];
  for (let i = 1; i <= 10; i++) {
    const email = `rca_user_${TS}_${i}@enterprisetest.com`;
    const password = `RcaUserPass@123${i}`;
    const phone = `+1 31255503${String(i).padStart(2, '0')}`;

    const res = await api('/api/users', {
      method: 'POST',
      token: primaryRca.token,
      body: JSON.stringify({
        firstName: `RcaUser${i}`,
        lastName: `Staff${i}`,
        email,
        password,
        phone,
        designation: 'Sales Rep'
      })
    });

    if (res.status === 201 && res.body?.data) {
      rcaUsers.push({ id: res.body.data._id || res.body.data.id, email, password });
      record(`RCA Created User #${i}`, true, `Email: ${email}`);
    } else {
      record(`RCA Created User #${i}`, false, `Status ${res.status}: ${JSON.stringify(res.body)}`);
    }
  }

  // Login as RCA-created Users
  for (let i = 0; i < rcaUsers.length; i++) {
    const usr = rcaUsers[i];
    const logRes = await api('/api/auth/login', {
      method: 'POST',
      body: JSON.stringify({ email: usr.email, password: usr.password, role: 'user' })
    });
    if (logRes.ok && logRes.body?.token) {
      usr.token = logRes.body.token;
      record(`RCA User #${i + 1} Login`, true);
    } else {
      record(`RCA User #${i + 1} Login`, false, `Status ${logRes.status}: ${JSON.stringify(logRes.body)}`);
    }
  }

  // --------------------------------------------------------------------------
  // STEP 8: LEAD CREATION & ASSIGNMENT FOR DSA (20 Leads Created & Assigned)
  // --------------------------------------------------------------------------
  console.log(`\n--- STEP 8: LEAD CREATION & ASSIGNMENT UNDER DSA (20 Leads) ---`);
  const dsaLeads = [];
  for (let i = 1; i <= 20; i++) {
    const leadEmail = `lead_dsa_${TS}_${i}@clientmail.com`;
    const phone = `+1 80055504${String(i).padStart(2, '0')}`;

    const res = await api('/api/buildings', {
      method: 'POST',
      token: primaryDsa.token,
      body: JSON.stringify({
        buildingType: 'commercial',
        userInfo: {
          firstName: `CustomerDSA${i}`,
          lastName: `Client${i}`,
          email: leadEmail,
          phone,
          city: 'Chicago',
          state: 'IL'
        }
      })
    });

    if (res.status === 201 && res.body?.data) {
      const leadId = res.body.data._id;
      dsaLeads.push(leadId);
      record(`DSA Lead Created #${i}`, true, `ID: ${leadId}, Email: ${leadEmail}`);

      // Alternate: Assign to 10 DSA Users & Share with 10 DSA Admins
      if (i <= 10 && dsaUsers[i - 1]) {
        // Assign to DSA User
        const targetUser = dsaUsers[i - 1];
        const assignRes = await api(`/api/buildings/${leadId}/assign`, {
          method: 'POST',
          token: primaryDsa.token,
          body: JSON.stringify({
            users: [{ userId: targetUser.id, permissions: ['read', 'edit'] }]
          })
        });
        record(`Assign Lead #${i} to DSA User #${i}`, assignRes.ok, `User ID: ${targetUser.id}`);
      } else if (i > 10 && dsaAdmins[i - 11]) {
        // Share with DSA Admin (Data-Viewer)
        const targetAdm = dsaAdmins[i - 11];
        const shareRes = await api('/api/superadmin/leads/share', {
          method: 'POST',
          token: primaryDsa.token,
          body: JSON.stringify({
            leadIds: [leadId],
            adminId: targetAdm.id,
            note: 'Assigned for enterprise review'
          })
        });
        record(`Share Lead #${i} to DSA Admin #${i - 10}`, shareRes.ok, `Admin ID: ${targetAdm.id}`);
      }
    } else {
      record(`DSA Lead Created #${i}`, false, `Status ${res.status}: ${JSON.stringify(res.body)}`);
    }
  }

  // --------------------------------------------------------------------------
  // STEP 9: LEAD CREATION & ASSIGNMENT FOR RCA (10 Leads Created & Assigned)
  // --------------------------------------------------------------------------
  console.log(`\n--- STEP 9: LEAD CREATION & ASSIGNMENT UNDER RCA (10 Leads) ---`);
  const rcaLeads = [];
  for (let i = 1; i <= 10; i++) {
    const leadEmail = `lead_rca_${TS}_${i}@clientmail.com`;
    const phone = `+1 88855505${String(i).padStart(2, '0')}`;

    const res = await api('/api/buildings', {
      method: 'POST',
      token: primaryRca.token,
      body: JSON.stringify({
        buildingType: 'residential',
        userInfo: {
          firstName: `CustomerRCA${i}`,
          lastName: `Client${i}`,
          email: leadEmail,
          phone,
          city: 'Austin',
          state: 'TX'
        }
      })
    });

    if (res.status === 201 && res.body?.data) {
      const leadId = res.body.data._id;
      rcaLeads.push(leadId);
      record(`RCA Lead Created #${i}`, true, `ID: ${leadId}`);

      // Assign to RCA User
      if (rcaUsers[i - 1]) {
        const targetUser = rcaUsers[i - 1];
        const assignRes = await api(`/api/buildings/${leadId}/assign`, {
          method: 'POST',
          token: primaryRca.token,
          body: JSON.stringify({
            users: [{ userId: targetUser.id, permissions: ['read', 'edit', 'delete'] }]
          })
        });
        record(`Assign Lead #${i} to RCA User #${i}`, assignRes.ok, `User ID: ${targetUser.id}`);
      }
    } else {
      record(`RCA Lead Created #${i}`, false, `Status ${res.status}: ${JSON.stringify(res.body)}`);
    }
  }

  // --------------------------------------------------------------------------
  // STEP 10: VERIFY ASSIGNED LEADS APPEAR DECRYPTED IN USER PANELS
  // --------------------------------------------------------------------------
  console.log(`\n--- STEP 10: VERIFY USER VISIBILITY & DECRYPTION ---`);
  // Verify DSA Users see their assigned leads
  for (let i = 0; i < 10; i++) {
    const usr = dsaUsers[i];
    if (!usr?.token) continue;
    const leadsRes = await api('/api/buildings', { token: usr.token });
    const userLeads = leadsRes.body?.data || [];
    const hasAssigned = userLeads.length > 0;
    const decryptedEmail = userLeads[0]?.email || userLeads[0]?.userInfo?.email || '';
    const isCleanEmail = decryptedEmail.includes('@');
    record(
      `DSA User #${i + 1} sees assigned lead`,
      hasAssigned && isCleanEmail,
      `Count: ${userLeads.length}, Decrypted Customer Email: ${decryptedEmail}`
    );
  }

  // Verify RCA Users see their assigned leads
  for (let i = 0; i < 10; i++) {
    const usr = rcaUsers[i];
    if (!usr?.token) continue;
    const leadsRes = await api('/api/buildings', { token: usr.token });
    const userLeads = leadsRes.body?.data || [];
    const hasAssigned = userLeads.length > 0;
    const decryptedEmail = userLeads[0]?.email || userLeads[0]?.userInfo?.email || '';
    const isCleanEmail = decryptedEmail.includes('@');
    record(
      `RCA User #${i + 1} sees assigned lead`,
      hasAssigned && isCleanEmail,
      `Count: ${userLeads.length}, Decrypted Customer Email: ${decryptedEmail}`
    );
  }

  // Verify DSA Admins see their shared leads
  for (let i = 0; i < 10; i++) {
    const adm = dsaAdmins[i];
    if (!adm?.token) continue;
    const leadsRes = await api('/api/buildings', { token: adm.token });
    const admLeads = leadsRes.body?.data || [];
    const hasShared = admLeads.length > 0;
    const decryptedEmail = admLeads[0]?.email || admLeads[0]?.userInfo?.email || '';
    const isCleanEmail = decryptedEmail.includes('@');
    record(
      `DSA Admin #${i + 1} sees shared lead`,
      hasShared && isCleanEmail,
      `Count: ${admLeads.length}, Decrypted Customer Email: ${decryptedEmail}`
    );
  }

  // --------------------------------------------------------------------------
  // STEP 11: VERIFY DSA DASHBOARD STATS & COUNTERS
  // --------------------------------------------------------------------------
  console.log(`\n--- STEP 11: DSA DASHBOARD COUNTERS & SCOPING ---`);
  const dsaStats = await api('/api/superadmin/dashboard/stats', { token: primaryDsa.token });
  if (dsaStats.ok && dsaStats.body?.data) {
    const { totalAdmins, totalUsers, totalLeads } = dsaStats.body.data;
    record(
      'DSA Dashboard Stats',
      totalAdmins >= 10 && totalUsers >= 10 && totalLeads >= 20,
      `Admins: ${totalAdmins}, Users: ${totalUsers}, Leads: ${totalLeads}`
    );
  } else {
    record('DSA Dashboard Stats', false, `Status ${dsaStats.status}: ${JSON.stringify(dsaStats.body)}`);
  }

  // --------------------------------------------------------------------------
  // STEP 12: VERIFY NOTIFICATION BELL SYSTEM
  // --------------------------------------------------------------------------
  console.log(`\n--- STEP 12: IN-APP NOTIFICATIONS VERIFICATION ---`);
  const notifRes = await api('/api/notifications', { token: primaryDsa.token });
  if (notifRes.ok && Array.isArray(notifRes.body?.data)) {
    const notifs = notifRes.body.data;
    record('Notifications Fetch for DSA', notifs.length > 0, `Total notifications: ${notifs.length}`);

    if (notifs.length > 0) {
      const sampleId = notifs[0].id || notifs[0]._id;
      // Mark read
      const markRes = await api(`/api/notifications/${sampleId}/read`, {
        method: 'PATCH',
        token: primaryDsa.token
      });
      record('Mark Notification Read', markRes.ok, `ID: ${sampleId}`);

      // Delete one
      const delRes = await api(`/api/notifications/${sampleId}`, {
        method: 'DELETE',
        token: primaryDsa.token
      });
      record('Delete Single Notification', delRes.ok, `ID: ${sampleId}`);
    }
  } else {
    record('Notifications Fetch for DSA', false, `Status ${notifRes.status}`);
  }

  // --------------------------------------------------------------------------
  // STEP 13: ACCOUNT UNIQUENESS & SECURITY CHECKS
  // --------------------------------------------------------------------------
  console.log(`\n--- STEP 13: ACCOUNT UNIQUENESS & VALIDATION CHECKS ---`);
  // Attempt to create duplicate email for admin
  const dupEmail = createdRcas[0].email;
  const dupAdminRes = await api('/api/superadmin/admins', {
    method: 'POST',
    token: rsaToken,
    body: JSON.stringify({
      firstName: 'Duplicate',
      lastName: 'Admin',
      email: dupEmail,
      password: 'SomePassword123!',
      companyName: 'Duplicate Corp'
    })
  });
  record(
    'Reject Duplicate Admin Email (409 Conflict)',
    dupAdminRes.status === 409,
    `Status received: ${dupAdminRes.status}`
  );

  // Attempt to create user with existing admin email
  const dupUserRes = await api('/api/users', {
    method: 'POST',
    token: primaryRca.token,
    body: JSON.stringify({
      firstName: 'Duplicate',
      lastName: 'User',
      email: dupEmail,
      password: 'SomePassword123!'
    })
  });
  record(
    'Cross-Role Duplicate Check (Admin email cannot be reused for User)',
    dupUserRes.status === 409,
    `Status received: ${dupUserRes.status}`
  );

  // --------------------------------------------------------------------------
  // STEP 14: FRONTEND HEALTH CHECK
  // --------------------------------------------------------------------------
  console.log(`\n--- STEP 14: FRONTEND APP HEALTH CHECK ---`);
  try {
    const feLogin = await fetch('http://localhost:3000/leadManager/login');
    record('Frontend Login Page Available', feLogin.status === 200, `HTTP status ${feLogin.status}`);
  } catch (err) {
    record('Frontend Login Page Available', false, err.message);
  }

  // --------------------------------------------------------------------------
  // FINAL SUMMARY
  // --------------------------------------------------------------------------
  console.log(`\n=======================================================`);
  console.log(`📊 FINAL TEST REPORT`);
  console.log(`   Total Tests:  ${results.passed + results.failed}`);
  console.log(`   Passed:       ${results.passed}`);
  console.log(`   Failed:       ${results.failed}`);
  console.log(`   Success Rate: ${((results.passed / (results.passed + results.failed)) * 100).toFixed(1)}%`);
  console.log(`=======================================================`);

  if (results.failed > 0) {
    process.exit(1);
  }
}

run().catch((err) => {
  console.error('\n💥 Unexpected Fatal Error in Test Runner:', err);
  process.exit(1);
});
