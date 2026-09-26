
import express from "express";
import {createBuilding,getBuildings,assignUsersToBuilding,updateUserPermission,distributeLeads,updateBuilding,deleteBuilding,removeAssignedUser,updateStatus,getBuilding,createPublicBuilding} from "../controllers/buildingController.js";
import { authenticateJWT } from "../middlewares/auth.js";
import { allowRoles } from "../middlewares/roles.js";
import { tenantPasskeyContext } from "../middlewares/tenantPasskeyContext.js";

const router = express.Router();

// If a tenant passkey header is present, register it in the in-memory session
// so pre('save') hooks can unwrap the tenant DEK for PII encryption.
router.use(tenantPasskeyContext);

// Public route for Estimator (No Auth)
router.post("/public/create", createPublicBuilding);

// CRUD for leads
router.post("/", authenticateJWT, allowRoles(["admin", "superadmin", "user"]), createBuilding);
router.get("/", authenticateJWT, allowRoles(["admin", "superadmin", "user"]), getBuildings);
router.get("/:id", authenticateJWT, allowRoles(["admin", "superadmin", "user"]), getBuilding);
router.put("/:id", authenticateJWT, allowRoles(["admin", "superadmin", "user"]), updateBuilding);
router.delete("/:id", authenticateJWT, allowRoles(["admin", "superadmin", "user"]), deleteBuilding);

// Lead assignments & permissions
router.post("/:id/assign", authenticateJWT, allowRoles(["admin", "superadmin"]), assignUsersToBuilding); // multi-user assign
router.put("/:id/permissions", authenticateJWT, allowRoles(["admin", "superadmin"]), updateUserPermission);
router.delete("/:id/assign/:userId", authenticateJWT, allowRoles(["admin", "superadmin"]), removeAssignedUser);

// Other lead actions
router.post("/distribute", authenticateJWT, allowRoles(["admin", "superadmin"]), distributeLeads);
router.patch("/:id/status", authenticateJWT, allowRoles(["admin", "superadmin", "user"]), updateStatus);

export default router;