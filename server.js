require("dotenv").config();
const express = require("express");
const http = require("http");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const mongoose = require("mongoose");
const WebSocket = require("ws");

const app = express();
const server = http.createServer(app);
const wss = new WebSocket.Server({ server });

// Use JSON middleware to parse JSON request bodies
app.use(express.json()); // <-- Add this line

// In-memory connections map
const connections = new Map(); // { userId: { userSocket: WebSocket, mcuSocket: WebSocket } }

// Connect to MongoDB
mongoose
  .connect(process.env.MONGO_URI)
  .then(() => console.log("MongoDB connected"))
  .catch((err) => console.error("MongoDB connection error:", err));

// JWT Secret Key
const JWT_SECRET = process.env.JWT_SECRET;

// Define the User schema and model
const userSchema = new mongoose.Schema({
  email: { type: String, required: true, unique: true },
  password: { type: String, required: true },
});

const User = mongoose.model("User", userSchema, "Users");

// Basic endpoint to confirm the server is running
app.get("/", (req, res) => {
  res.send("Server Running");
});

// Registration Endpoint
app.post("/register", async (req, res) => {
  const { email, password } = req.body;

  if (!email || !password) {
    return res.status(400).json({ message: "Email and password are required." });
  }

  try {
    const existingUser = await User.findOne({ email });
    if (existingUser) {
      return res.status(409).json({ message: "Email is already registered." });
    }

    const hashedPassword = await bcrypt.hash(password, 10);
    const newUser = new User({ email, password: hashedPassword });
    await newUser.save();

    res.status(201).json({ message: "User registered successfully." });
  } catch (error) {
    console.error("Error during registration:", error);
    res.status(500).json({ message: "Internal server error." });
  }
});

// Login Endpoint
app.post("/login", async (req, res) => {
  const { email, password } = req.body;
  try {
    const user = await User.findOne({ email });
    if (!user) {
      return res.status(401).json({ message: "Invalid email or password." });
    }

    const passwordMatch = await bcrypt.compare(password, user.password);
    if (!passwordMatch) {
      return res.status(401).json({ message: "Invalid email or password." });
    }

    const token = jwt.sign({ id: user._id, email: user.email }, JWT_SECRET, {
      expiresIn: "1h",
    });

    res.status(200).json({ token });
  } catch (error) {
    console.error("Error during login:", error);
    res.status(500).json({ message: "Internal server error." });
  }
});

// WebSocket Authentication Middleware
async function authenticateConnection(token) {
  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    const user = await User.findById(decoded.id);
    return user ? decoded : null;
  } catch (error) {
    return null;
  }
}

// Handle WebSocket Connections
wss.on("connection", async (ws, req) => {
  const url = new URL(`http://${req.headers.host}${req.url}`);
  const token = url.searchParams.get("token");
  const userId = url.searchParams.get("userId");
  const clientType = url.searchParams.get("type"); // `user` or `mcu`

  // Log each parameter to verify
  console.log("WebSocket connection attempt:");
  console.log("  Token:", token);
  console.log("  User ID:", userId);
  console.log("  Client Type:", clientType);

  if (!token || !userId || !clientType) {
    ws.close(1008, "Unauthorized: Missing token, userId, or client type");
    return;
  }

  const user = await authenticateConnection(token);
  if (!user || user.id !== userId) {
    ws.close(1008, "Unauthorized: Invalid token or userId mismatch");
    return;
  }

  console.log(`WebSocket connection established for user ID: ${userId} as ${clientType}`);

  // Store the connection in the map
  if (!connections.has(userId)) {
    connections.set(userId, { userSocket: null, mcuSocket: null });
  }

  // Update the connection map based on client type
  if (clientType === "user") {
    connections.get(userId).userSocket = ws;
  } else if (clientType === "mcu") {
    connections.get(userId).mcuSocket = ws;
  }


  //Sending data periodically to the client
  const intervalId = setInterval(() => {
    const randomNumber = Math.floor(Math.random() * 100);
    const jsonNum = JSON.stringify({ number: randomNumber });
    console.log(`Sending random number: ${jsonNum}`);
    ws.send(jsonNum);
  }, 10000);

  // // Relay data from MCU to User
  // if (clientType === "mcu" && connections.get(userId).userSocket) {
  //   ws.on("message", (message) => {
  //     console.log(`Received data from MCU for user ID ${userId}: ${message}`);
  //     const userSocket = connections.get(userId).userSocket;
  //     if (userSocket && userSocket.readyState === WebSocket.OPEN) {
  //       userSocket.send(message); // Send data from MCU to User
  //     }
  //   });
  // }

  // Handle WebSocket close events
  ws.on("close", () => {
    console.log(`WebSocket connection closed for user ID: ${userId} as ${clientType}`);
    const connection = connections.get(userId);
    if (clientType === "user") {
      connection.userSocket = null;
    } else if (clientType === "mcu") {
      connection.mcuSocket = null;
    }

    // Remove the entry if both connections are null
    if (!connection.userSocket && !connection.mcuSocket) {
      connections.delete(userId);
    }
  });
});

// Start the server
const PORT = process.env.PORT;
server.listen(PORT, '127.0.0.1', () => {
  console.log(`Server is running on port ${PORT}`);
});
