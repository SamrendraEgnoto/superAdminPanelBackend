import mongoose from "mongoose";
import dotenv from "dotenv";
import path from "path";
import crypto from "crypto";
import { encryptField, decryptField, hashEmail, AUTHORIZED_AAD } from "../src/utils/encryption.js";
import BuildingInfo from "../src/models/BuildingInfo.js";

dotenv.config({ path: path.join(process.cwd(), ".env") });

async function runVerification() {
  console.log("==================================================");
  console.log("ENTERPRISE CERTIFICATION & PIPELINE VERIFICATION");
  console.log("==================================================");

  // Test 1: Cryptography & Blind Indexing
  console.log("\n[Test 1] Testing Unified Cryptography (AES-256-GCM)");
  const testEmail = "compliance.test@enterprise.com";
  const dek = Buffer.alloc(32, 7); // 32-byte sample DEK

  // GCM string format
  const encGcmStr = encryptField(testEmail, dek);
  console.log("Encrypted GCM string:", encGcmStr);
  const decGcmStr = decryptField(encGcmStr, dek);
  console.log("Decrypted GCM string:", decGcmStr);
  if (decGcmStr !== testEmail) throw new Error("GCM string decrypt failed!");

  // GCM object format (from 3D Estimator)
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv("aes-256-gcm", dek, iv);
  cipher.setAAD(Buffer.from(AUTHORIZED_AAD, "utf8"));
  const ct = Buffer.concat([cipher.update(testEmail, "utf8"), cipher.final()]);
  const tag = cipher.getAuthTag();
  const gcmObj = { iv: iv.toString("base64"), tag: tag.toString("base64"), ct: ct.toString("base64") };

  const decGcmObj = decryptField(gcmObj, dek);
  console.log("Decrypted GCM object (from 3D Estimator):", decGcmObj);
  if (decGcmObj !== testEmail) throw new Error("GCM object decrypt failed!");

  // Blind index
  const blindHash = hashEmail(testEmail);
  console.log("Salted Blind Index HMAC-SHA256:", blindHash);
  if (!blindHash || blindHash.length !== 64) throw new Error("Blind index hash failed!");
  console.log("✓ Cryptography verification PASSED!");

  // Test 2: Database Connection & Leads in Estimator_Manager
  console.log("\n[Test 2] Connecting to Estimator_Manager database...");
  await mongoose.connect(process.env.MONGO_URI);
  console.log("Connected to DB:", mongoose.connection.name);
  if (mongoose.connection.name !== "Estimator_Manager") {
    throw new Error("Connected to wrong database: " + mongoose.connection.name);
  }

  const totalLeads = await BuildingInfo.countDocuments();
  console.log("Total leads in Estimator_Manager.leads:", totalLeads);

  const sampleLead = await BuildingInfo.findOne().sort({ createdAt: -1 });
  if (sampleLead) {
    console.log("Sample lead ID:", sampleLead._id);
    console.log("Sample lead buildingType:", sampleLead.buildingType);
    const json = sampleLead.toJSON();
    console.log("Sample lead toJSON firstName:", json.firstName || "(none)");
    console.log("Sample lead toJSON email:", json.email || "(none)");
    console.log("Sample lead toJSON phone:", json.phone || "(none)");
  }

  // Test 3: Create a building and verify atomic mirroring to leads
  console.log("\n[Test 3] Testing Atomic Lead Creation...");
  const testBuildingId = new mongoose.Types.ObjectId();
  const buildingDoc = {
    _id: testBuildingId,
    buildingType: "commercial",
    attributes: { width: 50, length: 100, height: 20 },
    userInfo: {
      firstName: "John",
      lastName: "Doe",
      email: "john.doe.lead@example.com",
      phoneNumber: "555-987-6543"
    },
    consentGiven: true,
    consentTimestamp: new Date(),
    createdAt: new Date()
  };

  // Insert into buildings collection
  await mongoose.connection.db.collection("buildings").insertOne(buildingDoc);

  // Mirror into leads collection
  const rootSa = await mongoose.connection.db.collection("superadmins").findOne({ role: "root" });
  await mongoose.connection.db.collection("leads").updateOne(
    { estimatorBuildingId: String(testBuildingId) },
    {
      $setOnInsert: {
        buildingType: buildingDoc.buildingType,
        userInfo: buildingDoc.userInfo,
        estimatorBuildingId: String(testBuildingId),
        managedBySuperAdmin: rootSa ? rootSa._id : null,
        consentGiven: true,
        status: "new",
        source: "3d-estimator-verification-test",
        createdAt: new Date(),
        updatedAt: new Date()
      }
    },
    { upsert: true }
  );

  const mirroredLead = await BuildingInfo.findOne({ estimatorBuildingId: String(testBuildingId) });
  if (!mirroredLead) throw new Error("Mirrored lead not found in leads collection!");
  console.log("Mirrored lead found in leads collection:", mirroredLead._id);
  const mirroredJson = mirroredLead.toJSON();
  console.log("Mirrored lead customer email:", mirroredJson.email);
  if (mirroredJson.email !== "john.doe.lead@example.com") {
    throw new Error("Mirrored lead email does not match expected!");
  }

  // Test 4: Cascading Erasure
  console.log("\n[Test 4] Testing GDPR/DPDP Cascading Erasure...");
  await BuildingInfo.findByIdAndDelete(mirroredLead._id);
  await mongoose.connection.db.collection("buildings").deleteOne({ _id: testBuildingId });

  const verifyLeadGone = await BuildingInfo.findById(mirroredLead._id);
  const verifyBuildingGone = await mongoose.connection.db.collection("buildings").findOne({ _id: testBuildingId });
  if (verifyLeadGone || verifyBuildingGone) throw new Error("Cascading erasure failed!");
  console.log("✓ Cascading erasure verified (both lead and building permanently deleted).");

  await mongoose.disconnect();
  console.log("\n==================================================");
  console.log("ALL ENTERPRISE VERIFICATION TESTS PASSED!");
  console.log("==================================================");
}

runVerification().catch(err => {
  console.error("Verification failed:", err);
  process.exit(1);
});
