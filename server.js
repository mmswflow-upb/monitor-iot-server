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
const connectedDevices = new Map(); // Store connected devices as objects

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

//Store sockets associated with tokens
const sockets = new Map();

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

  //When user/device first connects, users have to populate a list of connected devices,
  //devices have to subscribe to the pub/sub channels and send their device objects
  const deviceId = url.searchParams.get("deviceId");
  const deviceName = url.searchParams.get("deviceName");
  const deviceType = url.searchParams.get("deviceType");

  if (clientType === "user") {
    //Request devices to send their device objects

    //Check if the user is already connected
    if (!sockets.has(token)) {
      sockets.set(token, ws);
      console.log("USER: ADDED SOCKET TO MAP");
    }

    await redisSubscriber.subscribe(userId, (err) => {
      if (err) {
        console.error(`Failed to subscribe to channel ${userId}:`, err);
      } else {
        console.log(`USER: subbed to Redis channel`);
      }
    });
    redisPublisher.publish(userId, "getDevices");
  } else if (clientType === "mcu") {
    if (!deviceId || !deviceName || !deviceType) {
      ws.close(1008, "Unauthorized: Missing deviceId, deviceName, deviceType");
      return;
    }

    if (!sockets.has(token)) {
      console.log("MCU: ADDED SOCKET TO MAP");
      sockets.set(token, ws);
    }

    deviceObj = createDeviceObj(deviceId, userId, deviceName, deviceType, {});

    await redisSubscriber.subscribe(userId, (err) => {
      if (err) {
        console.error(`Failed to subscribe to channel ${userId}:`, err);
      } else {
        console.log(`${deviceName} subbed to Redis channel`);
      }
    });

    redisPublisher.publish(userId, JSON.stringify(deviceObj));
  }

  // Handle WebSocket closure
  ws.on("close", () => {
    console.log(`WebSocket connection closed for user ${userId}`);

    sockets.delete(token);

    // Unsubscribe from Redis channel
    redisSubscriber.unsubscribe(userId, (err) => {
      if (err)
        console.error(`Failed to unsubscribe from channel ${userId}:`, err);
      else console.log(`Unsubscribed from Redis channel for user ${userId}`);
    });

    //If a device disconnected, it must be removed from the list of connected devices
    if (clientType === "mcu") {
      redisPublisher.publish(
        userId,
        JSON.stringify({ removeDevice: true, deviceId: deviceObj["deviceId"] })
      );
    }
  });

  // WebSocket message handling
  ws.on("message", (content) => {
    content = JSON.parse(content);

    //Device updated its state, so it must be sent to the user
    if (content["type"] === "pong") {
      return;
    }

    if (clientType === "user") {
      // User is updating the state of a device
      if (content["deviceId"] && content["data"]) {
        console.log("USER UPDATING DEVICE OBJECT: ", content);

        // Adding message type as updateDevice
        const messageContent = {
          ...content,
          messageType: "updateDevice", // Marking the type of the message
        };
        redisPublisher.publish(userId, JSON.stringify(messageContent));
      }
    } else if (clientType === "mcu") {
      deviceObj = content;
      console.log("DEVICE UPDATED ITS OBJECT, publishing to Redis:", deviceObj);

      // Adding message type as updateDevice
      const messageContent = {
        ...deviceObj,
        messageType: "updateDevice", // Marking the type of the message
      };
      redisPublisher.publish(userId, JSON.stringify(messageContent));
    }
  });

  // Handling Redis messages with added messageType
  redisSubscriber.on("message", async (incomingUserId, content) => {
    if (userId != incomingUserId) {
      return;
    }

    // Parse the content to check message type
    const parsedContent = JSON.parse(content);

    // Check for messageType and handle accordingly
    if (clientType === "user") {
      console.log("USER RECEIVED content from Redis: ", parsedContent);
      if (
        parsedContent["messageType"] === "removeDevice" &&
        parsedContent["deviceId"]
      ) {
        connectedDevices.delete(parsedContent["deviceId"]);
        console.log(
          "USER: DELETING device with ID: ",
          parsedContent["deviceId"]
        );
      } else if (
        parsedContent["messageType"] === "updateDevice" &&
        parsedContent["deviceId"]
      ) {
        connectedDevices.set(parsedContent["deviceId"], parsedContent);
        console.log(
          "USER: UPDATING connected device: ",
          parsedContent["deviceName"]
        );

        // Send list of connected devices to user through socket
        if (sockets.has(token)) {
          console.log("USER: Sending list of connected devices to user");
          sockets.get(token).send(
            JSON.stringify({
              devices: Array.from(connectedDevices.values()),
              messageType: "updateDevice", // Marking the type of the message
            })
          );
        }
      }
    } else if (clientType === "mcu") {
      console.log("MCU: RECEIVED content from Redis: ", parsedContent);
      if (parsedContent["messageType"] === "getDevices") {
        redisPublisher.publish(userId, JSON.stringify(deviceObj));
        console.log(
          "DEVICE: USER REQUESTED device objects, sending device object: ",
          deviceObj["deviceName"]
        );
      } else if (
        parsedContent["messageType"] === "updateDevice" &&
        parsedContent["deviceId"] === deviceObj["deviceId"]
      ) {
        deviceObj["data"] = parsedContent["data"];
        if (sockets.has(token)) {
          console.log("MCU: Sending updated device object to MCU");
          sockets.get(token).send(JSON.stringify(deviceObj));
        }
      }
    }
  });

  //Set up a keep-alive interval and handle ping/pong
  let pingTimeout;

  const sendPing = () => {
    if (ws.readyState === WebSocket.OPEN) {
      if (sockets.has(token)) {
        console.log("Sending ping to keep connection alive");
        sockets
          .get(token)
          .send(JSON.stringify({ type: "ping", message: "keep-alive" }));
      }
      // Start a timeout to wait for pong
      pingTimeout = setTimeout(() => {
        sockets.delete(token);
        redisSubscriber.unsubscribe(userId);
        ws.close(); // Close the connection if pong is not received in time
      }, 10000); // Wait 10 seconds for the pong
    }
  };

  // Set an interval to send ping every 50 seconds
  const interval = setInterval(sendPing, 50000); // Send a ping every 50 seconds

  // Handle incoming pong responses
  ws.on("message", (message) => {
    const content = JSON.parse(message);
    if (content.type === "pong") {
      clearTimeout(pingTimeout); // Clear the timeout if pong is received
    }
  });

  // Clear the keep-alive interval on WebSocket closure
  ws.on("close", () => {
    clearInterval(interval);
    clearTimeout(pingTimeout); // Clear any existing timeout
  });
});

//Receives socket and data as object then applies json stringify to data and sends it through the socket
// async function sendDataThruSocket(token, data) {
//   console.log("SENDING DATA THRU SOCKET:", data);
//   socket = sockets.get(token);
//   if (socket.readyState === WebSocket.OPEN) {
//     try {
//       socket.send(JSON.stringify(data));
//       return true;
//     } catch (err) {
//       console.error("Error sending data through socket:", err);
//     }
//   }
//   return false;
// }

// Function to create a device object
function createDeviceObj(deviceId, userId, deviceName, deviceType, data) {
  return {
    deviceId: deviceId,
    userId: userId,
    deviceName: deviceName,
    deviceType: deviceType,
    data: data,
  };
}

server.listen(HTTP_PORT, () => {
  console.log(`Server running on port ${HTTP_PORT}`);
});
