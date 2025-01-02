require("dotenv").config();
const express = require("express");
const http = require("http");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const mongoose = require("mongoose");
const WebSocket = require("ws");
const Redis = require("ioredis");

// store the latest frame for each device,
// and a list of response objects (clients) for streaming.
const frames = {}; // { deviceId: Buffer (JPEG data) }
const streamSubscribers = {}; // { deviceId: [res1, res2, ...] }

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

//  Endpoint for MCU to upload frames in raw JPEG form
//    We use route-level middleware to accept raw binary data (image/jpeg).
app.post(
  "/uploadFrame/:deviceId",
  express.raw({ type: "image/jpeg", limit: "10mb" }), // Accept raw JPEG up to 10 MB
  (req, res) => {
    const { deviceId } = req.params;
    if (!req.body || !req.body.length) {
      return res.status(400).send("No frame data received.");
    }

    // Store the latest frame in memory
    frames[deviceId] = req.body;

    // Broadcast to any connected stream subscribers
    if (streamSubscribers[deviceId]) {
      for (let response of streamSubscribers[deviceId]) {
        response.write(`--frame\r\nContent-Type: image/jpeg\r\n\r\n`);
        response.write(req.body);
        response.write("\r\n");
      }
    }

    return res.status(200).send("Frame uploaded successfully.");
  }
);

// Endpoint for clients to consume the MJPEG stream
//    We'll serve frames in multipart/x-mixed-replace format.
app.get("/stream/:deviceId", (req, res) => {
  const { deviceId } = req.params;

  // If no frames have been uploaded yet, we can return a 503 or keep waiting
  if (!frames[deviceId]) {
    return res.status(503).send("No frames available for this device.");
  }

  res.writeHead(200, {
    "Content-Type": "multipart/x-mixed-replace; boundary=frame",
    "Cache-Control": "no-cache",
    Connection: "keep-alive",
  });

  // Write the most recent frame immediately
  res.write(`--frame\r\nContent-Type: image/jpeg\r\n\r\n`);
  res.write(frames[deviceId]);
  res.write("\r\n");

  // Add this response to the list of subscribers
  if (!streamSubscribers[deviceId]) {
    streamSubscribers[deviceId] = [];
  }
  streamSubscribers[deviceId].push(res);

  // Clean up if client disconnects
  req.on("close", () => {
    streamSubscribers[deviceId] = streamSubscribers[deviceId].filter(
      (r) => r !== res
    );
  });
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
    return user;
  } catch (error) {
    return null;
  }
}

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
  console.log(`User Authenticated: ${user.email} (${clientType})`);
  if (!user || user.id !== userId) {
    ws.close(1008, "Unauthorized: Invalid token or userId mismatch");
    return;
  }

  //When user/device first connects, users have to populate a list of connected devices,
  //devices have to subscribe to the pub/sub channels and send their device objects
  const deviceId = url.searchParams.get("deviceId");
  const deviceName = url.searchParams.get("deviceName");
  const deviceType = url.searchParams.get("deviceType");
  var deviceObj = {};

  if (clientType === "user") {
    //Request devices to send their device objects

    await redisSubscriber.subscribe(userId, (err) => {
      if (err) {
        console.error(
          `Failed to subscribe to channel ${user.email} ${clientType}:`,
          err
        );
      } else {
        console.log(`${clientType} ${user.email}: SUBBED to Redis channel`);
      }
    });
    redisPublisher.publish(
      userId,
      JSON.stringify({ messageType: "getDevices" })
    );
  } else if (clientType === "mcu") {
    if (!deviceId || !deviceName || !deviceType) {
      ws.close(1008, "Unauthorized: Missing deviceId, deviceName, deviceType");
      return;
    }

    deviceObj = createDeviceObj(deviceId, userId, deviceName, deviceType, {});

    await redisSubscriber.subscribe(userId, (err) => {
      if (err) {
        console.error(
          `Failed to subscribe to channel ${clientType} ${user.email}:`,
          err
        );
      } else {
        console.log(`${clientType} ${deviceName}: SUBBED to Redis channel`);
      }
    });

    redisPublisher.publish(
      userId,
      JSON.stringify({ messageType: "mcuUpdatesDevice", deviceObj: deviceObj })
    );
  }

  // Handling Redis messages with added messageType
  redisSubscriber.on("message", async (incomingUserId, content) => {
    if (userId !== incomingUserId) {
      return;
    }

    if (ws.readyState !== WebSocket.OPEN) {
      return;
    }

    // Parse the content to check message type
    const parsedContent = JSON.parse(content);

    // Check for messageType and handle accordingly
    if (clientType === "user") {
      // Handle removing a device
      if (
        parsedContent["messageType"] === "removeDevice" &&
        parsedContent["deviceId"]
      ) {
        connectedDevices.delete(parsedContent["deviceId"]);
        console.log(
          `${user.email} REMOVING device with ID ${parsedContent["deviceId"]} from connected devices`
        );

        // Optionally, send updated device list to the user
        console.log(
          `${user.email}: SENDING updated list of connected devices to client app`
        );
        ws.send(
          JSON.stringify({
            devices: Array.from(connectedDevices.values()),
            messageType: "updateDevicesList", // Marking the type of the message
          })
        );
      }

      // Handle updating a device by the user
      else if (
        parsedContent["messageType"] === "mcuUpdatesDevice" &&
        parsedContent["deviceObj"]
      ) {
        connectedDevices.set(
          parsedContent["deviceObj"]["deviceId"],
          parsedContent["deviceObj"]
        );
        console.log(
          `${clientType} ${user.email}: UPDATING connected device: ${parsedContent["deviceObj"]["deviceName"]}`
        );

        // Send updated list of connected devices to the user
        console.log(
          `${clientType} ${user.email}: SENDING updated list of connected devices to client app`
        );
        ws.send(
          JSON.stringify({
            devices: Array.from(connectedDevices.values()),
            messageType: "updateDevicesList", // Marking the type of the message
          })
        );
      }
    } else if (clientType === "mcu") {
      console.log(`${deviceName}: RECEIVED message from Redis`);
      // Handle getting devices request
      if (parsedContent["messageType"] === "getDevices") {
        // Publish the device object when requested
        redisPublisher.publish(
          userId,
          JSON.stringify({
            messageType: "mcuUpdatesDevice", // Include messageType in the published content
            deviceObj: deviceObj,
          })
        );
        console.log(
          `${deviceName}: ${user.email} REQUESTED device objects, sending device object `
        );
      }

      // Handle updating device from MCU
      else if (
        parsedContent["messageType"] === "userUpdatesDevice" &&
        parsedContent["deviceObj"]["deviceId"] === deviceObj["deviceId"]
      ) {
        // Update the device object data
        deviceObj["data"] = parsedContent["deviceObj"]["data"];
        console.log(`${deviceName}: UPDATED BY USER ${user.email}`);

        // If the socket exists, send the updated device object to the MCU
        console.log(
          `${clientType} ${deviceName}: SENDING updated device object to MCU`
        );
        ws.send(JSON.stringify(deviceObj));
      } else if (parsedContent["messageType"] === "userDisconnected") {
        console.log(`${clientType} ${deviceName}: USER STOPPED`);
        ws.send(JSON.stringify({ messageType: "userDisconnected" }));
      }
    }
  });

  //Set up a keep-alive interval and handle ping/pong
  let pingTimeout;

  const sendPing = () => {
    if (ws.readyState === WebSocket.OPEN) {
      ws.send(JSON.stringify({ messageType: "ping", message: "keep-alive" }));
    }

    // Start a timeout to wait for pong
    pingTimeout = setTimeout(
      async () => {
        // Close the connection if pong is not received in time
        console.log(
          `${clientType} ${
            deviceId === null ? user.email : deviceName
          }: NO PONG RECEIVED, closing websocket connection`
        );

        ws.terminate();
      },
      clientType === "user" ? 3000 : 6000
    ); // Wait 3 seconds for the pong for users, 6 seconds for devices
  };

  // Set an interval to send ping every 50 seconds (user) or 20 seconds (mcu)
  const interval = setInterval(sendPing, clientType === "user" ? 50000 : 20000);

  // WebSocket message handling
  ws.on("message", async (content) => {
    content = JSON.parse(content);

    //Device updated its state, so it must be sent to the user
    if (content["messageType"] === "pong") {
      clearTimeout(pingTimeout); // Clear the timeout if pong
      return;
    }

    if (clientType === "user") {
      // User is updating the state of a device
      if (content["deviceId"] && content["data"]) {
        console.log(
          `${clientType} ${user.email}: UPDATING DEVICE OBJECT: ${content["deviceName"]} `
        );

        // Adding message type as updateDevice
        const messageContent = {
          deviceObj: content,
          messageType: "userUpdatesDevice", // Marking the type of the message
        };
        await redisPublisher.publish(userId, JSON.stringify(messageContent));
      }
    } else if (clientType === "mcu") {
      deviceObj = content;
      console.log(
        `${clientType} ${deviceName} UPDATED ITS OBJECT, publishing to Redis`
      );

      // Adding message type as updateDevice
      const messageContent = {
        deviceObj: content,
        messageType: "mcuUpdatesDevice", // Marking the type of the message
      };
      await redisPublisher.publish(userId, JSON.stringify(messageContent));
    }
  });

  // Handle WebSocket closure
  ws.on("close", async () => {
    console.log(
      `${
        deviceId === null ? user.email : deviceName
      }: CLOSED websocket connection`
    );

    clearInterval(interval);
    clearTimeout(pingTimeout); // Clear any existing timeout

    //If a device disconnected, it must be removed from the list of connected devices
    if (clientType === "mcu") {
      console.log(`${clientType} ${deviceName}: DISCONNECTED`);
      await redisPublisher.publish(
        userId,
        JSON.stringify({
          messageType: "removeDevice",
          deviceId: deviceObj["deviceId"],
        })
      );
    } else if (clientType === "user") {
      console.log(`${clientType} ${user.email}: DISCONNECTED`);
      await redisPublisher.publish(
        userId,
        JSON.stringify({
          messageType: "userDisconnected",
          userId: userId,
        })
      );
    }

    // Unsubscribe from Redis channel
    await redisSubscriber.unsubscribe(userId, (err) => {
      if (err)
        console.error(
          `Failed to unsubscribe from channel ${clientType} ${userId}:`,
          err
        );
      else
        console.log(
          `${clientType} ${
            deviceId === null ? user.email : deviceName
          }: UNSUBSCRIBED from Redis channel`
        );
    });
  });
});

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
