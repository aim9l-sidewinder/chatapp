const express = require("express");
const http = require("http");
const WebSocket = require("ws");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const cors = require("cors");
const db = require("./db");
const path = require("path");

const SECRET = "super-secret-key";

const app = express();

// ---------------- CORE MIDDLEWARE ----------------
app.use(cors());
app.use(express.json());
app.use(express.static(path.join(__dirname, "public")));

// ---------------- AUTH ----------------

// Register
app.post("/register", async (req, res) => {
    const { username, password } = req.body || {};

    if (!username || !password) {
        return res.status(400).json({ error: "Missing fields" });
    }

    const hash = await bcrypt.hash(password, 10);

    db.run(
        "INSERT INTO users (username, password) VALUES (?, ?)",
        [username, hash],
        function (err) {
            if (err) {
                return res.status(400).json({ error: "User exists" });
            }
            res.json({ success: true });
        }
    );
});

// Login
app.post("/login", (req, res) => {
    const { username, password } = req.body || {};

    db.get(
        "SELECT * FROM users WHERE username = ?",
        [username],
        async (err, user) => {
            if (err) {
                return res.status(500).json({ error: "DB error" });
            }

            if (!user) {
                return res.status(401).json({ error: "Invalid login" });
            }

            const ok = await bcrypt.compare(password, user.password);
            if (!ok) {
                return res.status(401).json({ error: "Invalid login" });
            }

            const token = jwt.sign({ username }, SECRET);
            res.json({ token });
        }
    );
});

// ---------------- HTTP + WS ----------------
const server = http.createServer(app);
const wss = new WebSocket.Server({ server });

function verifyToken(token) {
    try {
        return jwt.verify(token, SECRET);
    } catch {
        return null;
    }
}

// Rooms
const rooms = new Map();

// ---------------- WS ----------------
wss.on("connection", (ws) => {
    let user = null;
    let authed = false;
    let room = "lobby";

    function joinRoom(r) {
        if (rooms.has(room)) rooms.get(room).delete(ws);

        room = r;

        if (!rooms.has(room)) rooms.set(room, new Set());
        rooms.get(room).add(ws);
    }

    joinRoom(room);

    ws.on("message", (data) => {
        let msg;
        try {
            msg = JSON.parse(data);
        } catch {
            return;
        }

        // AUTH
        if (msg.type === "auth") {
            const decoded = verifyToken(msg.token);
            if (!decoded) return ws.close();

            user = decoded.username;
            authed = true;

            ws.send(JSON.stringify({ type: "auth_ok", user }));

            broadcast(room, {
                type: "system",
                text: `${user} joined ${room}`
            });

            return;
        }

        if (!authed) return;

        // CHAT
        if (msg.type === "chat") {
            const payload = {
                type: "chat",
                username: user,
                text: msg.text
            };

            broadcast(room, payload);

            db.run(
                "INSERT INTO messages (username, text) VALUES (?, ?)",
                [user, msg.text]
            );
        }

        // ROOM SWITCH
        if (msg.type === "join_room") {
            broadcast(room, {
                type: "system",
                text: `${user} left ${room}`
            });

            joinRoom(msg.room);

            ws.send(JSON.stringify({ type: "room_joined", room }));

            broadcast(room, {
                type: "system",
                text: `${user} joined ${room}`
            });
        }
    });

    ws.on("close", () => {
        if (rooms.has(room)) {
            rooms.get(room).delete(ws);
        }

        broadcast(room, {
            type: "system",
            text: `${user || "Someone"} left`
        });
    });

    function broadcast(r, msg) {
        const json = JSON.stringify(msg);

        rooms.get(r)?.forEach(client => {
            if (client.readyState === WebSocket.OPEN) {
                client.send(json);
            }
        });
    }
});

// ---------------- START ----------------
server.listen(8080, "0.0.0.0", () => {
    console.log("Server running on http://localhost:8080");
	console.log("Server running on http://10.0.0.9:8080");
});