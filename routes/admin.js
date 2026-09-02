import express from "express";
import authenticate from "../middleware/authenticate.js";
import authorizeRole from "../middleware/authorize.js";
import { readUsers } from "../utils/db.js";

const router = express.Router();

export default router;

router.get("/users", authenticate, authorizeRole("admin"), (req, res) => {
  const users = readUsers().map(({ passwordHash, ...user }) => user);
  res.json({ users });
});
