require("dotenv").config();
const express = require("express");
const http = require("http");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const mongoose = require("mongoose");
const WebSocket = require("ws");
const Redis = require("ioredis");

const app = express();
const HTTP_PORT = process.env.PORT || 8080;
const JWT_SECRET = process.env.JWT_SECRET;

// Redis setup
const redisSubscriber = new Redis(process.env.REDISCLOUD_URL); // Redis subscriber for Pub/Sub
const redisPublisher = new Redis(process.env.REDISCLOUD_URL); // Redis publisher for Pub/Sub

// Handle Redis connection errors
redisSubscriber.on("error", (err) => {
  console.error("Redis Subscriber Error:", err);
});
redisPublisher.on("error", (err) => {
  console.error("Redis Publisher Error:", err);
});

// MongoDB setup
mongoose
  .connect(process.env.MONGO_URI, {
    connectTimeoutMS: 30000,
    socketTimeoutMS: 30000,
  })
  .then(() => console.log("MongoDB connected"))
  .catch((err) => console.error("MongoDB connection error:", err));

// User schema and model
const userSchema = new mongoose.Schema({
  email: { type: String, required: true, unique: true },
  password: { type: String, required: true },
});
const User = mongoose.model("User", userSchema, "Users");

// Middleware
app.use(express.json());

// Basic endpoint
app.get("/", (req, res) => {
  res.send("Server Running");
});

// Registration endpoint
app.post("/register", async (req, res) => {
  const { email, password } = req.body;

  if (!email || !password) {
    return res
      .status(400)
      .json({ message: "Email and password are required." });
  }

  try {
    const hashedPassword = await bcrypt.hash(password, 10);
    const newUser = new User({ email, password: hashedPassword });
    await newUser.save();
    res.status(201).json({ message: "User registered successfully." });
  } catch (error) {
    console.error("Registration error:", error);
    res.status(500).json({ message: "Internal server error." });
  }
});

// Login endpoint
app.post("/login", async (req, res) => {
  const { email, password } = req.body;

  try {
    const user = await User.findOne({ email });
    if (!user) {
      return res.status(401).json({ message: "Invalid email or password." });
    }

    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) {
      return res.status(401).json({ message: "Invalid email or password." });
    }

    const token = jwt.sign({ id: user._id }, JWT_SECRET, { expiresIn: "1h" });
    res.status(200).json({ token });
  } catch (error) {
    console.error("Login error:", error);
    res.status(500).json({ message: "Internal server error." });
  }
});

// WebSocket server setup
const server = http.createServer(app);
const wss = new WebSocket.Server({ server });
const connections = new Map(); // Store connections by userId

// WebSocket authentication
async function authenticateConnection(token) {
  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    const user = await User.findById(decoded.id);
    return user ? decoded : null;
  } catch (error) {
    return null;
  }
}

// WebSocket connection handling
wss.on("connection", async (ws, req) => {
  const url = new URL(`http://${req.headers.host}${req.url}`);
  const token = url.searchParams.get("token");
  const userId = url.searchParams.get("userId");
  const clientType = url.searchParams.get("type");

  if (!token || !userId || !clientType) {
    ws.close(1008, "Unauthorized: Missing token, userId, or client type");
    return;
  }

  const user = await authenticateConnection(token);
  if (!user || user.id !== userId) {
    ws.close(1008, "Unauthorized: Invalid token or userId mismatch");
    return;
  }

  console.log(
    `WebSocket connection established for user ${userId}, type: ${clientType}`
  );

  // Store the connection
  if (!connections.has(userId)) {
    connections.set(userId, []);
  }
  connections.get(userId).push(ws);

  // Subscribe to Redis channel for this user
  redisSubscriber.subscribe(userId, (err) => {
    if (err) console.error(`Failed to subscribe to channel ${userId}:`, err);
    else console.log(`Subscribed to channel ${userId}`);
  });

  // Listen for messages on the Redis channel
  redisSubscriber.on("message", (channel, message) => {
    if (channel === userId) {
      connections.get(userId)?.forEach((socket) => {
        if (socket.readyState === WebSocket.OPEN) {
          socket.send(message); // Send the message to the WebSocket connection
        }
      });
    }
  });

  // Handle incoming WebSocket messages
  ws.on("message", (data) => {
    console.log(`Received message from user ${userId}:`, data);

    try {
      // Publish the message to the Redis channel
      redisPublisher.publish(userId, data);
    } catch (err) {
      console.error(`Error publishing message to channel ${userId}:`, err);
    }
  });

  // Handle WebSocket closure
  ws.on("close", () => {
    console.log(`WebSocket connection closed for user ${userId}`);
    const userConnections = connections.get(userId) || [];
    connections.set(
      userId,
      userConnections.filter((socket) => socket !== ws)
    );

    if (connections.get(userId)?.length === 0) {
      connections.delete(userId);
      redisSubscriber.unsubscribe(userId);
    }
  });
});

// Start server
server.listen(HTTP_PORT, () => {
  console.log(`Server running on port ${HTTP_PORT}`);
});
