// ============================
// BACKEND (server.js)
// ============================

require("dotenv").config();
const express = require("express");
const http = require("http");
const WebSocket = require("ws");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const cors = require("cors");
const path = require("path");
const sqlite3 = require("sqlite3").verbose();

const SECRET = process.env.JWT_SECRET || "dev-secret";
const PORT = process.env.PORT || 8080;

const db = new sqlite3.Database("chat.db");

// Init DB
db.serialize(() => {
  db.run(`CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE,
    password TEXT
  )`);

  db.run(`CREATE TABLE IF NOT EXISTS messages (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT,
    text TEXT,
    room TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
  )`);
});

const app = express();
app.use(cors());
app.use(express.json());
app.use(express.static(path.join(__dirname, "public")));

// -------- AUTH --------
app.post("/register", async (req, res) => {
  const { username, password } = req.body || {};
  if (!username || !password) return res.status(400).json({ error: "Missing fields" });

  const hash = await bcrypt.hash(password, 10);

  db.run("INSERT INTO users (username, password) VALUES (?, ?)",
    [username, hash],
    function (err) {
      if (err) return res.status(400).json({ error: "User exists" });
      res.json({ success: true });
    }
  );
});

app.post("/login", (req, res) => {
  const { username, password } = req.body || {};

  db.get("SELECT * FROM users WHERE username = ?", [username], async (err, user) => {
    if (err) return res.status(500).json({ error: "DB error" });
    if (!user) return res.status(401).json({ error: "Invalid login" });

    const ok = await bcrypt.compare(password, user.password);
    if (!ok) return res.status(401).json({ error: "Invalid login" });

    const token = jwt.sign({ username }, SECRET, { expiresIn: "24h" });
    res.json({ token });
  });
});

// -------- SERVER --------
const server = http.createServer(app);
const wss = new WebSocket.Server({ server });

function verifyToken(token) {
  try { return jwt.verify(token, SECRET); }
  catch { return null; }
}
server.listen(PORT, () => console.log(`Server running on http://localhost:${PORT}`));
