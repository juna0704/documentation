# 🌐 **Network Protocols Explained with Code**

## 🎯 **The Big Picture: Network Layers**

Think of network communication like sending a package:

```
📦 Application Layer (Your API)     ← YOU WORK HERE
    ↓
🚚 Transport Layer (TCP/UDP)        ← How data moves
    ↓
🛣️ Network Layer (IP)              ← Addresses and routing
    ↓
📡 Physical Layer (Cables/WiFi)     ← Actual transmission
```

Your API protocols live at the **Application Layer** - they're the "language" your apps speak.

---

## 1️⃣ **HTTP: The Universal Language**

### **Basic HTTP Request/Response**

```javascript
// Client Side (Browser or Node.js)
fetch("https://api.example.com/users/123", {
  method: "GET",
  headers: {
    Authorization: "Bearer token123",
    "Content-Type": "application/json",
  },
})
  .then((response) => {
    console.log("Status:", response.status); // 200, 404, 500
    console.log("Headers:", response.headers.get("Content-Type"));
    return response.json();
  })
  .then((data) => console.log("Data:", data));

// Server Side (Node.js with Express)
const express = require("express");
const app = express();

// HTTP Methods in Action
app.get("/users/:id", (req, res) => {
  // GET - Read user
  const user = findUser(req.params.id);
  res.status(200).json(user);
});

app.post("/users", (req, res) => {
  // POST - Create user
  const newUser = createUser(req.body);
  res.status(201).json(newUser); // 201 = Created
});

app.put("/users/:id", (req, res) => {
  // PUT - Replace entire user
  updateUser(req.params.id, req.body);
  res.status(200).json({ message: "Updated" });
});

app.delete("/users/:id", (req, res) => {
  // DELETE - Remove user
  deleteUser(req.params.id);
  res.status(204).send(); // 204 = No Content
});

// Common Status Codes
app.get("/protected", (req, res) => {
  if (!req.headers.authorization) {
    return res.status(401).json({ error: "Unauthorized" }); // Need login
  }

  if (!hasPermission(req.user)) {
    return res.status(403).json({ error: "Forbidden" }); // Logged in but no permission
  }

  if (resourceNotFound()) {
    return res.status(404).json({ error: "Not Found" });
  }

  res.status(200).json({ data: "Success!" });
});
```

### **What's Actually Sent Over the Wire**

```http
# HTTP Request (raw format)
GET /users/123 HTTP/1.1
Host: api.example.com
Authorization: Bearer token123
Accept: application/json
User-Agent: MyApp/1.0

# HTTP Response (raw format)
HTTP/1.1 200 OK
Content-Type: application/json
Content-Length: 89
Date: Mon, 15 Jan 2024 10:00:00 GMT

{
  "id": "123",
  "name": "John Doe",
  "email": "john@example.com"
}
```

---

## 2️⃣ **HTTPS: HTTP with a Security Guard**

### **The Difference is Automatic**

```javascript
// ❌ HTTP (Insecure - anyone can read)
//api.example.com/users
// Data travels as plain text: "password=1234" → Anyone on network can see!

// ✅ HTTPS (Encrypted - secure tunnel)
http: //api.example.com/users
// Data travels as: "gT8#kL3$mN9*" → Only server can decrypt

// In code, it's the SAME! Just use https://
https: fetch("https://secure-api.com/data", {
  // Same code as HTTP
});

// Server setup (difference is in configuration)
const https = require("https");
const fs = require("fs");

const options = {
  key: fs.readFileSync("private-key.pem"),
  cert: fs.readFileSync("certificate.pem"),
};

https.createServer(options, app).listen(443);
```

### **Why HTTPS Everywhere?**

1. **Encryption**: Like sending mail in a locked safe
2. **Data Integrity**: Ensures no one tampered with your data in transit
3. **Authentication**: Proves you're talking to the real server (not an imposter)
4. **SEO**: Google ranks HTTPS sites higher
5. **Modern Browsers**: Mark HTTP sites as "Not Secure"

---

## 3️⃣ **WebSockets: The Real-Time Telephone**

### **The HTTP Polling Problem**

```javascript
// ❌ HTTP Polling (Chat App - BAD WAY)
function pollForMessages() {
  setInterval(() => {
    fetch("/api/messages")
      .then((res) => res.json())
      .then((messages) => {
        // 90% of the time: Empty array - wasted request!
        if (messages.length > 0) {
          displayMessages(messages);
        }
      });
  }, 1000); // Check every second
  // Wastes bandwidth, battery, server resources
  // High latency (up to 1 second delay)
}
```

### **WebSocket Solution**

```javascript
// ✅ WebSocket (Chat App - GOOD WAY)
// Client Side
const socket = new WebSocket("wss://chat.example.com");

socket.onopen = () => {
  console.log("Connected!");
  socket.send(JSON.stringify({ type: "join", room: "general" }));
};

socket.onmessage = (event) => {
  const message = JSON.parse(event.data);
  displayMessage(message); // INSTANT delivery
};

socket.onclose = () => {
  console.log("Disconnected");
};

// Send a message
function sendMessage(text) {
  socket.send(
    JSON.stringify({
      type: "message",
      text: text,
    })
  );
}

// Server Side (Node.js with ws library)
const WebSocket = require("ws");
const wss = new WebSocket.Server({ port: 8080 });

wss.on("connection", (ws) => {
  console.log("New client connected");

  ws.on("message", (data) => {
    const message = JSON.parse(data);

    // Broadcast to all connected clients
    wss.clients.forEach((client) => {
      if (client.readyState === WebSocket.OPEN) {
        client.send(JSON.stringify(message));
      }
    });
  });

  ws.on("close", () => {
    console.log("Client disconnected");
  });
});
```

### **How WebSockets Work**

```
Step 1: HTTP Handshake (Upgrade request)
Client: "Can we switch to WebSocket?"
Server: "OK, switching protocol"

Step 2: Persistent Connection
Both sides can talk anytime without asking
Like a phone call vs texting
```

**Use Cases**: Chat apps, live notifications, collaborative editing, stock tickers, multiplayer games.

---

## 4️⃣ **AMQP: The Reliable Message Queue**

### **The Producer-Consumer Pattern**

```javascript
// 🏭 Producer (Order Service)
const amqp = require("amqplib");

async function sendOrderToQueue(order) {
  const connection = await amqp.connect("amqp://localhost");
  const channel = await connection.createChannel();

  const queue = "order_processing";

  // Ensure queue exists
  await channel.assertQueue(queue, { durable: true });

  // Send message (will wait in queue until processed)
  channel.sendToQueue(queue, Buffer.from(JSON.stringify(order)), {
    persistent: true, // Survive server restart
  });

  console.log(`Order ${order.id} sent to queue`);
  await channel.close();
  await connection.close();
}

// Example: New order comes in
const newOrder = {
  id: "order_123",
  userId: "user_456",
  items: [{ productId: "prod_789", quantity: 2 }],
  total: 99.98,
};

sendOrderToQueue(newOrder);

// 🏭 Consumer (Payment Processor)
async function processOrders() {
  const connection = await amqp.connect("amqp://localhost");
  const channel = await connection.createChannel();

  const queue = "order_processing";
  await channel.assertQueue(queue, { durable: true });

  // Fair dispatch - don't overwhelm one consumer
  channel.prefetch(1);

  console.log("Waiting for orders...");

  channel.consume(queue, async (msg) => {
    const order = JSON.parse(msg.content.toString());

    try {
      // Process payment (could take time)
      console.log(`Processing order ${order.id}`);
      await processPayment(order);

      // Acknowledge successful processing
      channel.ack(msg);
      console.log(`Order ${order.id} processed successfully`);
    } catch (error) {
      // Failed - put back in queue or dead letter queue
      console.error(`Failed to process order ${order.id}:`, error);
      channel.nack(msg, false, true); // Requeue
    }
  });
}

// Benefits:
// 1. Decoupling: Order service doesn't wait for payment processing
// 2. Reliability: Messages won't be lost if consumer crashes
// 3. Scalability: Add more consumers for high load
// 4. Load leveling: Smooth out traffic spikes
```

### **Exchange Types in AMQP**

```javascript
// Direct Exchange (1:1 routing)
// Message goes to specific queue based on routing key
channel.publish("direct_exchange", "user.notifications", message);

// Fanout Exchange (Broadcast)
// Message goes to ALL bound queues
channel.publish("fanout_exchange", "", message); // routing key ignored

// Topic Exchange (Pattern matching)
// Message goes to queues matching pattern
channel.publish("topic_exchange", "user.123.notification", message);
// Queues bound to: "user.*.notification" get it
```

**Use Cases**: Order processing, email sending, background jobs, microservices communication.

---

## 5️⃣ **gRPC: The High-Speed Intercom**

### **Protocol Buffers Definition**

```protobuf
// messages.proto file (Contract between services)
syntax = "proto3";

// Service definition
service UserService {
  rpc GetUser (UserRequest) returns (UserResponse);
  rpc CreateUser (CreateUserRequest) returns (UserResponse);
  rpc StreamUsers (StreamRequest) returns (stream UserResponse);
}

// Message definitions
message UserRequest {
  string user_id = 1;
}

message UserResponse {
  string id = 1;
  string name = 2;
  string email = 3;
  int32 age = 4;
}

message CreateUserRequest {
  string name = 1;
  string email = 2;
  int32 age = 3;
}

message StreamRequest {
  int32 batch_size = 1;
}
```

### **Server Implementation (Node.js)**

```javascript
const grpc = require("@grpc/grpc-js");
const protoLoader = require("@grpc/proto-loader");

// Load the .proto file
const packageDefinition = protoLoader.loadSync("messages.proto");
const protoDescriptor = grpc.loadPackageDefinition(packageDefinition);

// Implement the service
const userService = {
  GetUser: (call, callback) => {
    const userId = call.request.user_id;
    const user = findUserInDatabase(userId);

    callback(null, {
      id: user.id,
      name: user.name,
      email: user.email,
      age: user.age,
    });
  },

  CreateUser: (call, callback) => {
    const newUser = {
      name: call.request.name,
      email: call.request.email,
      age: call.request.age,
    };

    const savedUser = saveUserToDatabase(newUser);

    callback(null, {
      id: savedUser.id,
      name: savedUser.name,
      email: savedUser.email,
      age: savedUser.age,
    });
  },

  StreamUsers: (call) => {
    // Server-side streaming
    const users = getAllUsersFromDatabase();

    users.forEach((user, index) => {
      // Send each user individually
      call.write({
        id: user.id,
        name: user.name,
        email: user.email,
        age: user.age,
      });

      // Simulate delay
      if (index % 100 === 0) {
        setTimeout(() => {}, 10);
      }
    });

    call.end(); // Signal streaming complete
  },
};

// Start server
const server = new grpc.Server();
server.addService(protoDescriptor.UserService.service, userService);
server.bindAsync(
  "0.0.0.0:50051",
  grpc.ServerCredentials.createInsecure(),
  () => {
    server.start();
    console.log("gRPC server running on port 50051");
  }
);
```

### **Client Implementation**

```javascript
const grpc = require("@grpc/grpc-js");
const protoLoader = require("@grpc/proto-loader");

const packageDefinition = protoLoader.loadSync("messages.proto");
const protoDescriptor = grpc.loadPackageDefinition(packageDefinition);

const client = new protoDescriptor.UserService(
  "localhost:50051",
  grpc.credentials.createInsecure()
);

// Unary RPC (like HTTP request-response)
client.GetUser({ user_id: "123" }, (error, response) => {
  if (error) {
    console.error("Error:", error);
  } else {
    console.log("User:", response);
  }
});

// Streaming RPC
const stream = client.StreamUsers({ batch_size: 100 });
stream.on("data", (user) => {
  console.log("Received user:", user.name);
});
stream.on("end", () => {
  console.log("Stream ended");
});

// Benefits of gRPC:
// 1. Binary format = smaller payloads (vs JSON)
// 2. HTTP/2 = multiple requests over one connection
// 3. Auto-generated client code
// 4. Strong typing = fewer bugs
// 5. Built-in streaming support
```

### **gRPC vs REST Comparison**

```javascript
// Same user data, different formats:

// REST/JSON (Human-readable, larger)
{
  "id": "123",
  "name": "John Doe",
  "email": "john@example.com",
  "age": 30
}
// Size: ~100 bytes

// gRPC/Protocol Buffers (Binary, compact)
// Size: ~40 bytes (60% smaller!)
// Faster to parse (no JSON parsing)
```

**Use Cases**: Microservices communication, mobile apps to backend, real-time streaming, performance-critical systems.

---

## 🔄 **TCP vs UDP: The Transport Layer**

### **TCP: The Reliable Postal Service**

```javascript
// TCP guarantees delivery (like certified mail)
// Built into HTTP, WebSockets, gRPC automatically

// How TCP works:
1. Handshake: Client → "Hello?" Server → "Hello back!" Client → "OK!"
2. Reliable: If packet gets lost, resends it
3. Ordered: Packets arrive in correct order
4. Error checking: Detects corrupted data

// Use TCP for:
// - Web browsing (HTTP/HTTPS)
// - Email (SMTP)
// - File transfers
// - Database connections
// - Anything where data must arrive correctly
```

### **UDP: The Speedy Postcard**

```javascript
// UDP is fast but unreliable (like throwing postcards)

// How UDP works:
1. No handshake: Just sends data
2. No guarantees: Packets can be lost
3. No ordering: Packets can arrive out of order
4. No retries: Lost packets stay lost

// Use UDP for:
// - Video streaming (missing frame = brief glitch)
// - Voice calls (better to skip than wait)
// - Online gaming (speed > perfection)
// - DNS lookups (small, fast queries)

// Example: Video streaming would use UDP
// A dropped packet = tiny visual glitch for 1/30 second
// TCP would pause video to resend = worse experience!
```

---

## 🎯 **Choosing the Right Protocol: Decision Guide**

### **Quick Reference Table**

```javascript
const protocolGuide = {
  HTTP: {
    when: "Public APIs, Web/Mobile clients",
    why: "Universal support, easy debugging",
    example: "E-commerce API, weather service",
    code: "fetch('https://api.com/data')",
  },

  WebSockets: {
    when: "Real-time, bidirectional communication",
    why: "Low latency, server push capability",
    example: "Chat apps, live dashboards",
    code: "const ws = new WebSocket('wss://...')",
  },

  gRPC: {
    when: "Internal services, performance-critical",
    why: "High speed, streaming, strong typing",
    example: "Microservices, mobile backend",
    code: "client.GetUser({user_id: '123'}, callback)",
  },

  AMQP: {
    when: "Reliable message delivery, async processing",
    why: "Guaranteed delivery, decoupling",
    example: "Order processing, email queues",
    code: "channel.sendToQueue('orders', message)",
  },
};
```

### **Decision Flowchart**

```javascript
// Ask these questions:

1. Is this for a web browser?
   → Yes: HTTP or WebSockets
   → No: Continue

2. Need real-time, two-way communication?
   → Yes: WebSockets
   → No: Continue

3. Is this internal service-to-service?
   → Yes: Consider gRPC
   → No: Continue

4. Need guaranteed message delivery?
   → Yes: AMQP or HTTP with retries
   → No: HTTP

5. Performance critical?
   → Yes: gRPC (binary) over HTTP (JSON)

// Example scenarios:

// Public weather API → HTTP/HTTPS
// Chat application → WebSockets
// Microservices payment system → gRPC
// Order processing pipeline → AMQP
// File upload with progress → HTTP with streaming
```

### **Hybrid Approach (Real World)**

```javascript
// Most applications use multiple protocols!

// E-commerce Platform Example:
const ecommerceProtocols = {
  frontend: {
    // Browser to server
    productCatalog: "HTTP", // GET /products
    userAuthentication: "HTTP", // POST /login
    realTimeNotifications: "WebSockets", // New order alerts
  },

  backend: {
    // Microservices talking to each other
    inventoryService: "gRPC", // Fast, internal
    paymentService: "gRPC", // High performance needed
    emailService: "AMQP", // Queued, reliable delivery
    analyticsService: "HTTP", // External API
  },
};

// Implementation:
app.use("/api", httpRouter); // REST API
app.use("/ws", websocketHandler); // Real-time
grpcServer.start(); // Internal services
rabbitMQ.connect(); // Message queue
```

---

## 🚀 **Quick Start Examples**

### **Basic HTTP Server (Node.js)**

```javascript
const http = require("http");

const server = http.createServer((req, res) => {
  res.writeHead(200, { "Content-Type": "application/json" });
  res.end(JSON.stringify({ message: "Hello World" }));
});

server.listen(3000, () => {
  console.log("HTTP server running on port 3000");
});
```

### **Basic WebSocket Server**

```javascript
const WebSocket = require("ws");
const wss = new WebSocket.Server({ port: 8080 });

wss.on("connection", (ws) => {
  ws.on("message", (message) => {
    console.log("Received:", message);
    ws.send(`Echo: ${message}`);
  });
});
```

### **Quick gRPC Setup**

```bash
# 1. Define your .proto file
# 2. Generate code
protoc --js_out=import_style=commonjs,binary:. messages.proto

# 3. Implement server and client
```

---

## 📊 **Performance Comparison**

```javascript
// Rough performance characteristics:

const protocolPerformance = {
  latency: {
    gRPC: "⭐⭐⭐⭐⭐ (Fastest - binary + HTTP/2)",
    WebSockets: "⭐⭐⭐⭐ (Low after connection)",
    HTTP: "⭐⭐⭐ (Good for most use cases)",
    AMQP: "⭐⭐ (Queue adds delay)",
  },

  bandwidth: {
    gRPC: "⭐⭐⭐⭐⭐ (Binary = smallest)",
    HTTP: "⭐⭐⭐ (JSON = larger)",
    WebSockets: "⭐⭐⭐⭐ (Efficient after setup)",
    AMQP: "⭐⭐⭐ (Similar to HTTP)",
  },

  developerExperience: {
    HTTP: "⭐⭐⭐⭐⭐ (Everyone knows it)",
    WebSockets: "⭐⭐⭐⭐ (Pretty straightforward)",
    gRPC: "⭐⭐⭐ (Learning curve)",
    AMQP: "⭐⭐⭐ (Queue concepts to learn)",
  },
};
```

---

> **Remember**: Start with HTTP for simplicity. Add WebSockets when you need real-time. Use gRPC for internal performance. Choose AMQP for reliable queuing. The best solution often uses multiple protocols together!

**Your next step**: Build a simple HTTP API, then add WebSocket support for one real-time feature. You'll quickly understand when each protocol shines. 🌟
