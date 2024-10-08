// server.js
require("dotenv").config();
const express = require("express");
const http = require("http");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const fs = require("fs");
const WebSocket = require("ws");

const app = express();
const server = http.createServer(app);
const wss = new WebSocket.Server({ server });

app.use(express.json());

// Load users from a JSON file (for simplicity)
const usersFile = "./data/users.json";

// Function to read users from the file
function readUsers() {
  if (!fs.existsSync(usersFile)) {
    fs.writeFileSync(usersFile, JSON.stringify([]));
  }
  const data = fs.readFileSync(usersFile);
  return JSON.parse(data);
}

// Function to write users to the file
function writeUsers(users) {
  fs.writeFileSync(usersFile, JSON.stringify(users, null, 2));
}

// JWT Secret Key
const JWT_SECRET = process.env.JWT_SECRET || "your-secret-key";

// Respond with "Server Running" for browser access
app.get("/", (req, res) => {
  res.send("Server Running");
});

/// Registration Endpoint
app.post("/register", async (req, res) => {
  const { email, password } = req.body;

  // Basic validation
  if (!email || !password) {
    return res
      .status(400)
      .json({ message: "Email and password are required." });
  }

  const users = readUsers();
  const existingUser = users.find((user) => user.email === email);

  if (existingUser) {
    return res.status(409).json({ message: "Email is already registered." });
  }

  try {
    const hashedPassword = await bcrypt.hash(password, 10);
    const newUser = {
      id: users.length + 1,
      email,
      password: hashedPassword,
    };
    users.push(newUser);
    writeUsers(users);

    res.status(201).json({ message: "User registered successfully." });
  } catch (error) {
    console.error("Error during registration:", error);
    res.status(500).json({ message: "Internal server error." });
  }
});

/// Login Endpoint
app.post("/login", async (req, res) => {
  const { email, password } = req.body;

  const users = readUsers();
  const user = users.find((user) => user.email === email);

  if (!user) {
    return res.status(401).json({ message: "Invalid email or password." });
  }

  try {
    const passwordMatch = await bcrypt.compare(password, user.password);

    if (passwordMatch) {
      const token = jwt.sign({ id: user.id, email: user.email }, JWT_SECRET, {
        expiresIn: "1h",
      });

      res.status(200).json({ token });
    } else {
      res.status(401).json({ message: "Invalid email or password." });
    }
  } catch (error) {
    console.error("Error during login:", error);
    res.status(500).json({ message: "Internal server error." });
  }
});

// WebSocket Authentication Middleware
function authenticateConnection(info, callback) {
  const url = new URL(`http://${info.req.headers.host}${info.req.url}`);
  const token = url.searchParams.get("token");

  if (!token) {
    callback(false, 401, "Unauthorized");
    return;
  }

  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    info.req.user = decoded;
    callback(true);
  } catch (error) {
    callback(false, 401, "Unauthorized");
  }
}

// Handle WebSocket Connections
wss.on("connection", (ws, req) => {
  console.log(`New WebSocket connection from user ID: ${req.user.id}`);

  // Send random numbers every 10 seconds
  const intervalId = setInterval(() => {
    const randomNumber = Math.floor(Math.random() * 100);
    ws.send(JSON.stringify({ number: randomNumber }));
  }, 10000);

  ws.on("close", () => {
    console.log(`WebSocket connection closed for user ID: ${req.user.id}`);
    clearInterval(intervalId);
  });
});

// Apply the authentication middleware
wss.on("headers", (headers, req) => {
  authenticateConnection(req, (auth, code, message) => {
    if (!auth) {
      req.destroy();
    }
  });
});

// Start the server
const PORT = process.env.PORT || 8080;
server.listen(PORT, () => {
  console.log(`Server is running on port ${PORT}`);
});
