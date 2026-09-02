import express from "express";
import { findByEmail } from "../utils/db.js";
import randomUUID from "crypto";
import bcrypt from "bcryptjs";
import { readUsers, writeUsers } from "../utils/db.js";
import { signToken } from "../utils/jwt.js";
import { blacklistToken } from "../utils/token-blacklist.js";
import authenticate from "../middleware/authenticate.js";

const router = express.Router();

export default router;

router.post("/register", async (req, res) => {
  const email = req.body.email;
  const password = req.body.password;

  if (!email || !password) {
    res.status(400).json({ message: "Email and password are required" });
    res.end;
  }
  if (findByEmail(email)) {
    res.status(409).json({ message: "Email already in use" });
  }

  const passwordHash = await bcrypt.hash(password, 10);
  const newUser = {
    id: randomUUID,
    email: email,
    passwordHash: passwordHash,
    role: "user",
  };
  const users = readUsers();
  users.push(newUser);
  writeUsers(users);

  const token = signToken({
    id: newUser.id,
    email: newUser.email,
    role: newUser.role,
  });

  res.status(201).json({ message: "User created", token: token });
});

router.post("/login", async (req, res) => {
  const email = req.body.email;
  const password = req.body.password;

  if (!email || !password) {
    res.status(400).json({ message: "Email or password missing" });
    return;
  }
  const user = findByEmail(email);
  if (!user) {
    res.status(401).json({ message: "Invalid credentials" });
  }
  const match = await bcrypt.compare(password, user.passwordHash);
  if (!match) {
    res.status(401).json({ message: "Invalid credentials" });
    return;
  }
  const token = signToken({ id: user.id, email: user.email, role: user.role });
  res.status(200).json({ message: "Login successful", token: token });
});

router.get("/profile", authenticate, (req, res) => {
  res.status(200).json({ user: req.user });
});

router.post("/logout", authenticate, async (req, res) => {
  const token = req.headers.authorization.split(" ")[1];
  blacklistToken(token);
  res.status(200).json({ message: "Logged out successfully" });
});
