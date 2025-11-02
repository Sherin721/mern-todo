import express from "express";
import bcrypt from "bcryptjs";
import jwt from "jsonwebtoken";
import User from "../models/User.js";

const router = express.Router();

// Register
router.post("/register", async (req, res) => {
  const { name, email, password } = req.body;
  const existing = await User.findOne({ email });
  if (existing) return res.status(400).json({ message: "Email already exists" });

  const hashed = await bcrypt.hash(password, 10);
  const newUser = await User.create({ name, email, password: hashed });

  const token = jwt.sign({ id: newUser._id }, "secretkey", { expiresIn: "1d" });
  res.json({ token, user: { name: newUser.name, email: newUser.email } });
});

// Login
router.post("/login", async (req, res) => {
  const { email, password } = req.body;
  const user = await User.findOne({ email });
  if (!user) return res.status(400).json({ message: "Invalid credentials" });

  const match = await bcrypt.compare(password, user.password);
  if (!match) return res.status(400).json({ message: "Invalid credentials" });

  const token = jwt.sign({ id: user._id }, "secretkey", { expiresIn: "1d" });
  res.json({ token, user: { name: user.name, email: user.email } });
});

export default router;
