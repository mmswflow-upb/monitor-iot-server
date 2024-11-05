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
app.use(express.json());

// Connect to MongoDB
mongoose
  .connect(process.env.MONGO_URI, {
    connectTimeoutMS: 30000,
    socketTimeoutMS: 30000,
  })
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
    res.status(500).json({ message: `Internal server error at Register: ${error}` });
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
    res.status(500).json({ message: `Internal server error at Login: ${error}` });
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
const connections = new Map();

wss.on("connection", async (ws, req) => {
  const url = new URL(`http://${req.headers.host}${req.url}`);
  const token = url.searchParams.get("token");
  const userId = url.searchParams.get("userId");
  const clientType = url.searchParams.get("type");
  const deviceName = url.searchParams.get("deviceName");
  const deviceType = url.searchParams.get("deviceType");

  // Log each parameter to verify
  console.log("WebSocket connection attempt:");
  console.log("  Token:", token);
  console.log("  User ID:", userId);
  console.log("  Client Type:", clientType);
  console.log("  Device Name:", deviceName);
  console.log("  Device Type:", deviceType);

  // Check if token, userId, or clientType is missing
  if (!token || !userId || !clientType) {
    ws.close(1008, "Unauthorized: Missing token, userId, or client type");
    return;
  }

  // Additional validation if clientType is "mcu"
  if (clientType === "mcu" && (!deviceName || !deviceType)) {
    ws.close(1008, "Unauthorized: Missing deviceName or deviceType for MCU");
    return;
  }

  const user = await authenticateConnection(token);
  if (!user || user.id !== userId) {
    ws.close(1008, "Unauthorized: Invalid token or userId mismatch");
    return;
  }

  console.log(
    `WebSocket connection established for user ID: ${userId} as ${clientType}${
      deviceName ? ` with Device: ${deviceName}` : ""
    }`
  );

  // Store the connection in the map
  if (!connections.has(userId)) {
    connections.set(userId, { userSocket: null, mcuSockets: [] });
  }

  // Update the connection map based on client type
  if (clientType === "user") {
    connections.get(userId).userSocket = ws;
  } else if (clientType === "mcu") {
    connections.get(userId).mcuSockets.push({ ws, deviceName, deviceType });
  }

  //Sending data periodically to the client
  try {
    const intervalId = setInterval(() => {
      const randomNumber = Math.floor(Math.random() * 100);
      const jsonNum = JSON.stringify({ number: randomNumber });
      console.log(`Sending random number: ${jsonNum}`);
      ws.send(jsonNum);
    }, 10000);

    ws.on("close", () => {
      console.log(
        `WebSocket connection closed for user ID: ${userId}, clientType: ${clientType}${
          deviceName ? `, Device: ${deviceName}` : ""
        }`
      );
      clearInterval(intervalId);

      // Remove the closed connection from the map
      if (clientType === "mcu") {
        const userConnections = connections.get(userId);
        userConnections.mcuSockets = userConnections.mcuSockets.filter(
          (connection) => connection.ws !== ws
        );
        if (userConnections.mcuSockets.length === 0 && !userConnections.userSocket) {
          connections.delete(userId);
        }
      } else if (clientType === "user") {
        const userConnections = connections.get(userId);
        userConnections.userSocket = null;
        if (!userConnections.mcuSockets.length) {
          connections.delete(userId);
        }
      }
    });
  } catch (error) {
    ws.close(4001, "Unauthorized - Invalid token");
  }
});

const PORT = process.env.PORT || 8080;
server.listen(PORT, process.env.HOSTNAME || null, () => {
  console.log(`Server is running on port ${PORT} and IP: ${server.address().address}`);
});
