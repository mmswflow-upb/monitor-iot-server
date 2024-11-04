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

app.use(express.json());

// MongoDB Connection aaaa
mongoose
  .connect(process.env.MONGO_URI)
  .then(() => console.log("MongoDB connected"))
  .catch((err) => console.error("MongoDB connection error: ", err));

// JWT Secret Key
const JWT_SECRET = process.env.JWT_SECRET || "your-secret-key";

// Define the User schema and model
const userSchema = new mongoose.Schema({
  email: { type: String, required: true, unique: true },
  password: { type: String, required: true },
});

const User = mongoose.model("User", userSchema, "Users");

// Respond with "Server Running" for browser access
app.get("/", (req, res) => {
  res.send("Server Running");
});

/// Registration Endpoint
app.post("/register", async (req, res) => {
  const { email, password } = req.body;

  if (!email || !password) {
    return res
      .status(400)
      .json({ message: "Email and password are required." });
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

/// Login Endpoint
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

// Middleware to verify JWT and check if the user exists
async function verifyToken(req, res, next) {
  const authHeader = req.headers["authorization"];
  const token = authHeader && authHeader.split(" ")[1];

  if (!token) {
    return res.status(401).json({ message: "No token provided." });
  }

  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    req.user = decoded;

    // Check if the user still exists in the database
    const user = await User.findById(decoded.id);
    if (!user) {
      return res.status(401).json({ message: "User no longer exists." });
    }

    next();
  } catch (error) {
    if (error.name === "TokenExpiredError") {
      return res.status(401).json({ message: "Token expired." });
    }
    return res.status(401).json({ message: "Invalid token." });
  }
}

// WebSocket Authentication Middleware
async function authenticateConnection(req, callback) {
  const url = new URL(`http://${req.headers.host}${req.url}`);
  const token = url.searchParams.get("token");

  if (!token) {
    callback(false, 401, "Unauthorized");
    return;
  }

  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    req.user = decoded;

    // Check if the user still exists in the database
    const user = await User.findById(decoded.id);
    if (!user) {
      callback(false, 401, "User no longer exists");
      return;
    }

    callback(true);
  } catch (error) {
    if (error.name === "TokenExpiredError") {
      callback(false, 401, "Token expired");
    } else {
      callback(false, 401, "Unauthorized");
    }
  }
}

// Handle WebSocket Connections
// Create a map to track active WebSocket connections with user IDs
const connections = new Map();

wss.on("connection", async (ws, req) => {
  // Extract token from the request URL
  const url = new URL(`http://${req.headers.host}${req.url}`);
  const token = url.searchParams.get("token");

  if (!token) {
    ws.close(401, "Unauthorized");
    return;
  }

  try {
    // Verify the token
    const decoded = jwt.verify(token, JWT_SECRET);
    const user = await User.findById(decoded.id);

    if (!user) {
      ws.close(401, "User does not exist");
      return;
    }

    // Token is valid and user exists.  Store WebSocket connection for the user ID
    connections.set(user._id.toString(), ws);
    console.log(`WebSocket connection established for user ID: ${user._id}`);

    //Sending data periodically to the client
    const intervalId = setInterval(() => {
      const randomNumber = Math.floor(Math.random() * 100);
      const jsonNum = JSON.stringify({ number: randomNumber });
      console.log(`Sending random number: ${jsonNum}`);
      ws.send(jsonNum);
    }, 10000);

    ws.on("close", () => {
      console.log(`WebSocket connection closed for user ID: ${req.user.id}`);
      clearInterval(intervalId);
    });
  } catch (error) {
    ws.close(4001, "Unauthorised - Invalid token");
  }
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
server.listen(PORT, process.env.HOSTNAME || null, () => {
  console.log(
    `Server is running on port ${PORT} and IP: ${server.address().address}`
  );
});
