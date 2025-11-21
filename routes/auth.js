// routes/auth.js
import { Router } from "express";
import bcrypt from "bcryptjs";
import jwt from "jsonwebtoken";
import pg from "pg";

const router = Router();

const db = new pg.Pool({
  connectionString: process.env.DATABASE_URL
});

const JWT_SECRET = process.env.JWT_SECRET || "dev_secret_key";

async function ensureUsersTable() {
  await db.query(`
    CREATE TABLE IF NOT EXISTS users (
      id SERIAL PRIMARY KEY,
      email TEXT UNIQUE NOT NULL,
      password_hash TEXT NOT NULL,
      created_at TIMESTAMPTZ DEFAULT NOW()
    );
  `);
}

ensureUsersTable();

// POST /auth/signup
router.post("/signup", async (req, res) => {
  try {
    const { email, password } = req.body || {};

    if (!email || !password || password.length < 8) {
      return res.status(400).json({
        error: "invalid_input",
        message: "Email and password with minimum length 8 required"
      });
    }

    const normalizedEmail = String(email).toLowerCase().trim();
    const hash = await bcrypt.hash(password, 10);

    let user;
    try {
      user = await db.query(
        `INSERT INTO users (email, password_hash)
         VALUES ($1, $2)
         RETURNING id, email, created_at`,
        [normalizedEmail, hash]
      );
    } catch (err) {
      if (err.code === "23505") {
        return res.status(409).json({
          error: "email_exists",
          message: "An account with this email already exists"
        });
      }
      throw err;
    }

    const token = jwt.sign(
      { user_id: user.rows[0].id, email: user.rows[0].email },
      JWT_SECRET,
      { expiresIn: "30d" }
    );

    return res.json({
      token,
      user: user.rows[0]
    });
  } catch (err) {
    console.error("Signup error:", err);
    res.status(500).json({ error: "internal_error" });
  }
});

// POST /auth/login
router.post("/login", async (req, res) => {
  try {
    const { email, password } = req.body || {};
    if (!email || !password) {
      return res.status(400).json({
        error: "invalid_input",
        message: "Email and password required"
      });
    }

    const normalizedEmail = String(email).toLowerCase().trim();

    const result = await db.query(
      `SELECT id, email, password_hash FROM users WHERE email = $1`,
      [normalizedEmail]
    );

    if (!result.rows.length) {
      return res.status(401).json({
        error: "invalid_credentials",
        message: "Incorrect email or password"
      });
    }

    const user = result.rows[0];
    const ok = await bcrypt.compare(password, user.password_hash);
    if (!ok) {
      return res.status(401).json({
        error: "invalid_credentials",
        message: "Incorrect email or password"
      });
    }

    const token = jwt.sign(
      { user_id: user.id, email: user.email },
      JWT_SECRET,
      { expiresIn: "30d" }
    );

    res.json({
      token,
      user: { id: user.id, email: user.email }
    });
  } catch (err) {
    console.error("Login error:", err);
    res.status(500).json({ error: "internal_error" });
  }
});

export default router;