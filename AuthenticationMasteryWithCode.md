# 🔐 **Authentication Mastery: From Basics to Production**

## 🎯 **The Authentication Mindset**

**Think of authentication like a nightclub:**

- **Basic Auth**: Shouting your name and password at the door (everyone hears it)
- **Bearer Token**: Having a wristband that gets you in (safer, but can be stolen)
- **OAuth 2.0**: Your famous friend vouching for you (delegated trust)
- **JWT**: A digital ID card with built-in expiration (self-contained proof)

---

## 1️⃣ **Basic Authentication: The Dangerous Simplicity**

### **How It Works (Don't Do This!)**

```javascript
// ❌ TERRIBLE - Basic Auth Example (for education only!)

// Client side (browser does this automatically)
const username = 'john';
const password = 'password123';
const credentials = btoa(`${username}:${password}`); // "am9objpwYXNzd29yZDEyMw=="

// Headers sent:
Authorization: Basic am9objpwYXNzd29yZDEyMw==

// Server side - NEVER DO THIS IN PRODUCTION
app.post('/login-basic', (req, res) => {
  const authHeader = req.headers.authorization; // "Basic am9objpwYXNzd29yZDEyMw=="
  const encoded = authHeader.split(' ')[1]; // "am9objpwYXNzd29yZDEyMw=="
  const decoded = Buffer.from(encoded, 'base64').toString(); // "john:password123"
  const [username, password] = decoded.split(':');

  // Check in database (plain text comparison - VERY BAD!)
  const user = users.find(u => u.username === username && u.password === password);

  if (user) {
    // User logged in (INSECURE!)
    res.json({ message: 'Logged in (insecurely)' });
  }
});
```

**Why It's Terrible:**

1. **Base64 is NOT encryption** - Anyone can decode it
2. **Password sent every request** - Like saying your password out loud each time
3. **No expiration** - Stolen credentials work forever
4. **No defense against replay attacks** - Same request works multiple times

**Only use case**: Internal tools behind VPN, with HTTPS, when nothing else works.

---

## 2️⃣ **Bearer Tokens: The Modern Standard**

### **How It Works**

```javascript
// ✅ PRODUCTION-READY - Bearer Token Implementation

// Login endpoint (returns token)
app.post("/login", async (req, res) => {
  const { email, password } = req.body;

  // 1. Find user
  const user = await db.users.findOne({ email });
  if (!user) {
    return res.status(401).json({ error: "Invalid credentials" });
  }

  // 2. Verify password (using bcrypt - NEVER store plain passwords!)
  const isValid = await bcrypt.compare(password, user.passwordHash);
  if (!isValid) {
    return res.status(401).json({ error: "Invalid credentials" });
  }

  // 3. Generate secure random token
  const token = crypto.randomBytes(32).toString("hex");

  // 4. Store token in database (with expiration)
  await db.sessions.create({
    userId: user.id,
    token,
    expiresAt: new Date(Date.now() + 24 * 60 * 60 * 1000), // 24 hours
    userAgent: req.headers["user-agent"],
    ipAddress: req.ip,
  });

  // 5. Send token to client
  res.json({
    token,
    user: { id: user.id, email: user.email, name: user.name },
  });
});

// Protected endpoint
app.get("/profile", async (req, res) => {
  // 1. Get token from header
  const authHeader = req.headers.authorization;
  if (!authHeader?.startsWith("Bearer ")) {
    return res.status(401).json({ error: "No token provided" });
  }

  const token = authHeader.split(" ")[1];

  // 2. Look up token in database
  const session = await db.sessions.findOne({
    token,
    expiresAt: { $gt: new Date() }, // Not expired
  });

  if (!session) {
    return res.status(401).json({ error: "Invalid or expired token" });
  }

  // 3. Get user data
  const user = await db.users.findOne({ id: session.userId });

  res.json({ user });
});

// Logout endpoint (important!)
app.post("/logout", async (req, res) => {
  const token = req.headers.authorization?.split(" ")[1];
  if (token) {
    await db.sessions.deleteOne({ token }); // Invalidate token
  }
  res.json({ message: "Logged out" });
});
```

### **Bearer Token Characteristics:**

```
✅ Pros:
- Stateless (server doesn't need to keep session)
- Scalable (easy to add more servers)
- Revocable (delete from database = logged out)
- Trackable (can log IP, device, etc.)

⚠️ Cons:
- Database lookup every request (performance)
- Token theft = account theft (mitigate with short expiry)
```

---

## 3️⃣ **JWT (JSON Web Tokens): The Self-Contained Solution**

### **How JWT Works**

```javascript
// ✅ JWT Implementation with proper security

const jwt = require("jsonwebtoken");

// Configuration
const JWT_SECRET = process.env.JWT_SECRET; // MUST be strong (256-bit)
const ACCESS_TOKEN_EXPIRY = "15m"; // Short-lived
const REFRESH_TOKEN_EXPIRY = "7d"; // Long-lived

// Generate tokens
function generateTokens(userId) {
  // Access token (short-lived, for API calls)
  const accessToken = jwt.sign(
    {
      userId,
      type: "access",
      iat: Math.floor(Date.now() / 1000), // issued at
    },
    JWT_SECRET,
    { expiresIn: ACCESS_TOKEN_EXPIRY }
  );

  // Refresh token (long-lived, for getting new access tokens)
  const refreshToken = jwt.sign(
    {
      userId,
      type: "refresh",
      iat: Math.floor(Date.now() / 1000),
    },
    JWT_SECRET,
    { expiresIn: REFRESH_TOKEN_EXPIRY }
  );

  return { accessToken, refreshToken };
}

// Login endpoint with JWT
app.post("/login-jwt", async (req, res) => {
  const { email, password } = req.body;

  // Verify credentials
  const user = await verifyCredentials(email, password);
  if (!user) {
    return res.status(401).json({ error: "Invalid credentials" });
  }

  // Generate tokens
  const { accessToken, refreshToken } = generateTokens(user.id);

  // Store refresh token in database (for invalidation)
  await db.refreshTokens.create({
    userId: user.id,
    token: refreshToken,
    expiresAt: new Date(Date.now() + 7 * 24 * 60 * 60 * 1000), // 7 days
  });

  // Send tokens (store refresh token as HTTP-only cookie for security)
  res
    .cookie("refreshToken", refreshToken, {
      httpOnly: true, // Cannot be accessed by JavaScript
      secure: process.env.NODE_ENV === "production", // HTTPS only
      sameSite: "strict", // Prevent CSRF
      maxAge: 7 * 24 * 60 * 60 * 1000, // 7 days
    })
    .json({
      accessToken,
      user: { id: user.id, email: user.email },
    });
});

// Verify JWT middleware
function authenticateJWT(req, res, next) {
  const authHeader = req.headers.authorization;

  if (!authHeader?.startsWith("Bearer ")) {
    return res.status(401).json({ error: "Access token required" });
  }

  const token = authHeader.split(" ")[1];

  try {
    // Verify token signature and expiration
    const decoded = jwt.verify(token, JWT_SECRET);

    // Check token type (must be access token)
    if (decoded.type !== "access") {
      return res.status(401).json({ error: "Invalid token type" });
    }

    // Add user to request
    req.user = { id: decoded.userId };
    next();
  } catch (error) {
    if (error.name === "TokenExpiredError") {
      return res.status(401).json({ error: "Token expired" });
    }
    return res.status(403).json({ error: "Invalid token" });
  }
}

// Protected route using JWT
app.get("/protected-data", authenticateJWT, (req, res) => {
  // req.user is available from middleware
  res.json({ message: `Hello user ${req.user.id}!` });
});

// Refresh token endpoint
app.post("/refresh-token", async (req, res) => {
  const refreshToken = req.cookies.refreshToken;

  if (!refreshToken) {
    return res.status(401).json({ error: "Refresh token required" });
  }

  try {
    // Verify refresh token
    const decoded = jwt.verify(refreshToken, JWT_SECRET);

    if (decoded.type !== "refresh") {
      return res.status(401).json({ error: "Invalid token type" });
    }

    // Check if refresh token exists in database (allows invalidation)
    const storedToken = await db.refreshTokens.findOne({
      token: refreshToken,
      userId: decoded.userId,
      expiresAt: { $gt: new Date() },
    });

    if (!storedToken) {
      return res.status(401).json({ error: "Invalid refresh token" });
    }

    // Generate new access token
    const { accessToken } = generateTokens(decoded.userId);

    res.json({ accessToken });
  } catch (error) {
    return res.status(403).json({ error: "Invalid refresh token" });
  }
});
```

### **JWT Structure Explained**

```javascript
// A JWT has 3 parts: header.payload.signature
const token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c";

// 1. HEADER (Base64 encoded)
{
  "alg": "HS256",  // Algorithm (HMAC SHA-256)
  "typ": "JWT"     // Type
}

// 2. PAYLOAD (Base64 encoded)
{
  "sub": "1234567890",  // Subject (user ID)
  "name": "John Doe",
  "iat": 1516239022,    // Issued at timestamp
  "exp": 1516242622     // Expiration timestamp
}

// 3. SIGNATURE
HMACSHA256(
  base64UrlEncode(header) + "." + base64UrlEncode(payload),
  secret
)
```

### **JWT Security Considerations:**

```javascript
// ⚠️ Common JWT Mistakes to Avoid:

// 1. Storing sensitive data in payload
// ❌ BAD: Token contains credit card info
{
  "userId": "123",
  "creditCard": "4111-1111-1111-1111" // DANGEROUS!
}

// ✅ GOOD: Only store non-sensitive identifiers
{
  "userId": "123",
  "role": "user"
}

// 2. Using weak secrets
// ❌ BAD: Weak secret
const secret = 'mysecret123'; // Too short, guessable

// ✅ GOOD: Strong, random secret
const secret = crypto.randomBytes(32).toString('hex'); // 256-bit

// 3. Not validating token type
// ❌ BAD: Accepting any token type
jwt.verify(token, secret); // Could be refresh token!

// ✅ GOOD: Check token type
const decoded = jwt.verify(token, secret);
if (decoded.type !== 'access') {
  throw new Error('Wrong token type');
}
```

---

## 4️⃣ **OAuth 2.0: The Delegated Authentication**

### **OAuth 2.0 Flow (Google Login Example)**

```javascript
// ✅ OAuth 2.0 Implementation

const { OAuth2Client } = require("google-auth-library");
const client = new OAuth2Client(process.env.GOOGLE_CLIENT_ID);

// 1. Client redirects user to Google
app.get("/auth/google", (req, res) => {
  const url = client.generateAuthUrl({
    access_type: "offline", // Get refresh token
    scope: ["email", "profile"], // What we want to access
    prompt: "consent", // Force consent screen
  });
  res.redirect(url);
});

// 2. Google redirects back with code
app.get("/auth/google/callback", async (req, res) => {
  const { code } = req.query;

  try {
    // 3. Exchange code for tokens
    const { tokens } = await client.getToken(code);

    // 4. Verify ID token
    const ticket = await client.verifyIdToken({
      idToken: tokens.id_token,
      audience: process.env.GOOGLE_CLIENT_ID,
    });

    const payload = ticket.getPayload();

    // 5. Extract user info
    const userInfo = {
      googleId: payload.sub,
      email: payload.email,
      name: payload.name,
      picture: payload.picture,
    };

    // 6. Find or create user in your database
    let user = await db.users.findOne({ googleId: userInfo.googleId });

    if (!user) {
      // First time login - create user
      user = await db.users.create({
        googleId: userInfo.googleId,
        email: userInfo.email,
        name: userInfo.name,
        avatar: userInfo.picture,
      });
    }

    // 7. Create your own JWT for the user
    const { accessToken, refreshToken } = generateTokens(user.id);

    // 8. Redirect to frontend with tokens
    res.redirect(
      `${process.env.FRONTEND_URL}/auth-success?token=${accessToken}`
    );
  } catch (error) {
    console.error("OAuth error:", error);
    res.redirect(`${process.env.FRONTEND_URL}/auth-error`);
  }
});

// Verify Google token on API calls
async function verifyGoogleToken(idToken) {
  const ticket = await client.verifyIdToken({
    idToken,
    audience: process.env.GOOGLE_CLIENT_ID,
  });
  return ticket.getPayload();
}
```

### **OAuth 2.0 Grant Types**

```javascript
// Different OAuth flows for different use cases:

// 1. Authorization Code (for web apps - most secure)
// User clicks "Login with Google" → Redirect to Google → Back with code → Exchange for token

// 2. Implicit (deprecated - don't use)
// ❌ Returns token directly in URL fragment (insecure)

// 3. Client Credentials (for server-to-server)
// Machine talks to machine, no user involved
app.post("/api/machine-auth", async (req, res) => {
  const { client_id, client_secret } = req.body;

  // Verify client credentials
  const client = await db.clients.findOne({
    client_id,
    client_secret,
  });

  if (!client) {
    return res.status(401).json({ error: "Invalid client credentials" });
  }

  // Issue machine token
  const token = jwt.sign({ client_id, scope: client.scope }, JWT_SECRET, {
    expiresIn: "1h",
  });

  res.json({ access_token: token, token_type: "Bearer" });
});

// 4. Password Grant (legacy - avoid if possible)
// ❌ User gives username/password directly to your app
// Only use for trusted first-party clients
```

---

## 5️⃣ **Access + Refresh Tokens: The Secure Combo**

### **Complete Implementation**

```javascript
// ✅ Complete Access/Refresh Token System

class AuthService {
  constructor() {
    this.accessTokenExpiry = "15m";
    this.refreshTokenExpiry = "7d";
  }

  async login(email, password) {
    // 1. Verify credentials
    const user = await this.verifyCredentials(email, password);

    // 2. Generate tokens
    const tokens = await this.generateTokenPair(user.id);

    // 3. Store refresh token (for invalidation)
    await this.storeRefreshToken(user.id, tokens.refreshToken);

    // 4. Return tokens (with different security levels)
    return {
      accessToken: tokens.accessToken,
      refreshToken: tokens.refreshToken, // Send as HTTP-only cookie
      user: {
        id: user.id,
        email: user.email,
        name: user.name,
      },
    };
  }

  async generateTokenPair(userId) {
    // Access token (short-lived, for API calls)
    const accessToken = jwt.sign(
      {
        sub: userId,
        type: "access",
        iat: Math.floor(Date.now() / 1000),
      },
      process.env.JWT_SECRET,
      { expiresIn: this.accessTokenExpiry }
    );

    // Refresh token (long-lived, for getting new access tokens)
    const refreshToken = jwt.sign(
      {
        sub: userId,
        type: "refresh",
        iat: Math.floor(Date.now() / 1000),
      },
      process.env.JWT_SECRET,
      { expiresIn: this.refreshTokenExpiry }
    );

    return { accessToken, refreshToken };
  }

  async refreshAccessToken(refreshToken) {
    try {
      // Verify refresh token
      const decoded = jwt.verify(refreshToken, process.env.JWT_SECRET);

      if (decoded.type !== "refresh") {
        throw new Error("Invalid token type");
      }

      // Check if refresh token exists and is valid
      const isValid = await this.validateRefreshToken(
        decoded.sub,
        refreshToken
      );
      if (!isValid) {
        throw new Error("Invalid refresh token");
      }

      // Generate new access token
      const accessToken = jwt.sign(
        {
          sub: decoded.sub,
          type: "access",
          iat: Math.floor(Date.now() / 1000),
        },
        process.env.JWT_SECRET,
        { expiresIn: this.accessTokenExpiry }
      );

      return { accessToken };
    } catch (error) {
      throw new Error("Token refresh failed");
    }
  }

  async logout(userId, refreshToken) {
    // Invalidate refresh token
    await this.invalidateRefreshToken(userId, refreshToken);

    // Optionally: Add token to blacklist
    await this.blacklistToken(refreshToken);
  }

  async blacklistToken(token) {
    // Store in Redis with TTL = token expiry
    const decoded = jwt.decode(token);
    const expiresIn = decoded.exp - Math.floor(Date.now() / 1000);

    if (expiresIn > 0) {
      await redis.setex(`blacklist:${token}`, expiresIn, "1");
    }
  }

  async isTokenBlacklisted(token) {
    return await redis.exists(`blacklist:${token}`);
  }
}

// Middleware to check blacklist
const checkBlacklist = async (req, res, next) => {
  const token = req.headers.authorization?.split(" ")[1];

  if (token && (await authService.isTokenBlacklisted(token))) {
    return res.status(401).json({ error: "Token revoked" });
  }

  next();
};
```

---

## 6️⃣ **SSO (Single Sign-On) & Identity Protocols**

### **SAML Implementation (Enterprise)**

```javascript
// SAML is XML-based, used in enterprises
const saml2 = require("saml2-js");

// Identity Provider (IdP) configuration
const idpConfig = {
  sso_login_url: "https://idp.company.com/sso/login",
  sso_logout_url: "https://idp.company.com/sso/logout",
  certificates: ["-----BEGIN CERTIFICATE-----\n..."],
};

// Service Provider (SP) configuration
const spConfig = {
  entity_id: "https://your-app.com/saml/metadata",
  private_key: fs.readFileSync("./key.pem"),
  certificate: fs.readFileSync("./cert.pem"),
  assert_endpoint: "https://your-app.com/saml/assert",
};

const sp = new saml2.ServiceProvider(spConfig);
const idp = new saml2.IdentityProvider(idpConfig);

// Generate login URL
app.get("/saml/login", (req, res) => {
  sp.create_login_request_url(idp, {}, (err, loginUrl) => {
    if (err) return res.status(500).send("Error");
    res.redirect(loginUrl);
  });
});

// Handle SAML response
app.post("/saml/assert", (req, res) => {
  const options = { request_body: req.body };

  sp.post_assert(idp, options, (err, samlResponse) => {
    if (err) return res.status(403).send("Auth failed");

    // Extract user attributes from SAML
    const user = {
      id: samlResponse.user.name_id,
      email: samlResponse.user.attributes.email,
      name: samlResponse.user.attributes.name,
      groups: samlResponse.user.attributes.groups,
    };

    // Create session
    const token = generateTokens(user.id);

    res.redirect("/dashboard?token=" + token);
  });
});
```

---

## 🛡️ **Production Security Additions**

### **Rate Limiting for Authentication**

```javascript
// Prevent brute force attacks
const rateLimit = require("express-rate-limit");

const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 5, // 5 attempts per IP
  message: { error: "Too many login attempts, try again later" },
  skipSuccessfulRequests: true, // Only count failed attempts
});

app.post("/login", authLimiter, async (req, res) => {
  // Login logic
});
```

### **Password Security**

```javascript
const bcrypt = require("bcrypt");
const validator = require("validator");

class PasswordService {
  async hashPassword(password) {
    // Validate password strength
    if (!this.isStrongPassword(password)) {
      throw new Error("Password too weak");
    }

    // Hash with bcrypt (salt included)
    const saltRounds = 12; // Higher = more secure but slower
    return await bcrypt.hash(password, saltRounds);
  }

  async verifyPassword(password, hash) {
    return await bcrypt.compare(password, hash);
  }

  isStrongPassword(password) {
    return (
      password.length >= 8 &&
      /[A-Z]/.test(password) && // Uppercase
      /[a-z]/.test(password) && // Lowercase
      /[0-9]/.test(password) && // Number
      /[^A-Za-z0-9]/.test(password) // Special char
    );
  }
}
```

### **Multi-Factor Authentication (MFA)**

```javascript
const speakeasy = require("speakeasy");
const QRCode = require("qrcode");

class MFAService {
  // Generate secret for new user
  generateSecret(userEmail) {
    const secret = speakeasy.generateSecret({
      name: `MyApp:${userEmail}`,
    });

    return {
      secret: secret.base32,
      otpauth_url: secret.otpauth_url,
    };
  }

  // Generate QR code for app
  async generateQRCode(otpauthUrl) {
    return await QRCode.toDataURL(otpauthUrl);
  }

  // Verify TOTP code
  verifyToken(secret, token) {
    return speakeasy.totp.verify({
      secret,
      encoding: "base32",
      token,
      window: 1, // Allow 30-second drift
    });
  }

  // Login with MFA
  async loginWithMFA(email, password, token) {
    // 1. Verify password
    const user = await verifyCredentials(email, password);

    // 2. Check if MFA is enabled
    if (user.mfaEnabled) {
      // 3. Verify MFA token
      const isValid = this.verifyToken(user.mfaSecret, token);
      if (!isValid) {
        throw new Error("Invalid MFA token");
      }
    }

    // 4. Generate session
    return generateTokens(user.id);
  }
}
```

---

## 🔄 **Complete Authentication Flow**

### **Step-by-Step Implementation**

```javascript
// 1. User Registration
app.post("/register", async (req, res) => {
  const { email, password, name } = req.body;

  // Validate input
  if (!validator.isEmail(email)) {
    return res.status(400).json({ error: "Invalid email" });
  }

  if (!passwordService.isStrongPassword(password)) {
    return res.status(400).json({
      error:
        "Password must be 8+ chars with uppercase, lowercase, number, and special char",
    });
  }

  // Check if user exists
  const existing = await db.users.findOne({ email });
  if (existing) {
    return res.status(409).json({ error: "User already exists" });
  }

  // Hash password
  const passwordHash = await passwordService.hashPassword(password);

  // Create user
  const user = await db.users.create({
    email,
    passwordHash,
    name,
    createdAt: new Date(),
  });

  // Generate email verification token
  const verifyToken = crypto.randomBytes(32).toString("hex");
  await db.verificationTokens.create({
    userId: user.id,
    token: verifyToken,
    expiresAt: new Date(Date.now() + 24 * 60 * 60 * 1000), // 24 hours
  });

  // Send verification email
  await emailService.sendVerificationEmail(email, verifyToken);

  res.status(201).json({
    message: "User created. Check email for verification.",
    userId: user.id,
  });
});

// 2. Email Verification
app.get("/verify-email", async (req, res) => {
  const { token } = req.query;

  const verification = await db.verificationTokens.findOne({
    token,
    expiresAt: { $gt: new Date() },
  });

  if (!verification) {
    return res.status(400).json({ error: "Invalid or expired token" });
  }

  // Mark user as verified
  await db.users.updateOne(
    { id: verification.userId },
    { emailVerified: true }
  );

  // Delete verification token
  await db.verificationTokens.deleteOne({ token });

  res.json({ message: "Email verified successfully" });
});

// 3. Login
app.post("/login", authLimiter, async (req, res) => {
  const { email, password } = req.body;

  // Find user
  const user = await db.users.findOne({ email });
  if (!user) {
    return res.status(401).json({ error: "Invalid credentials" });
  }

  // Check if email is verified
  if (!user.emailVerified) {
    return res.status(403).json({
      error: "Please verify your email first",
      needsVerification: true,
    });
  }

  // Verify password
  const isValid = await passwordService.verifyPassword(
    password,
    user.passwordHash
  );
  if (!isValid) {
    // Log failed attempt
    await db.failedLogins.create({
      email,
      ip: req.ip,
      userAgent: req.headers["user-agent"],
      timestamp: new Date(),
    });

    return res.status(401).json({ error: "Invalid credentials" });
  }

  // Check if MFA is required
  if (user.mfaEnabled) {
    // Return that MFA is needed
    return res.json({
      requiresMFA: true,
      userId: user.id,
    });
  }

  // Generate tokens
  const { accessToken, refreshToken } = await authService.generateTokenPair(
    user.id
  );

  // Store refresh token
  await authService.storeRefreshToken(user.id, refreshToken);

  // Set refresh token as HTTP-only cookie
  res.cookie("refreshToken", refreshToken, {
    httpOnly: true,
    secure: process.env.NODE_ENV === "production",
    sameSite: "strict",
    maxAge: 7 * 24 * 60 * 60 * 1000, // 7 days
  });

  // Return access token and user info
  res.json({
    accessToken,
    user: {
      id: user.id,
      email: user.email,
      name: user.name,
      mfaEnabled: user.mfaEnabled,
    },
  });
});

// 4. MFA Verification (if enabled)
app.post("/verify-mfa", async (req, res) => {
  const { userId, token } = req.body;

  const user = await db.users.findOne({ id: userId });
  if (!user || !user.mfaEnabled) {
    return res.status(400).json({ error: "MFA not enabled" });
  }

  const isValid = mfaService.verifyToken(user.mfaSecret, token);
  if (!isValid) {
    return res.status(401).json({ error: "Invalid MFA code" });
  }

  // Generate tokens (same as regular login)
  const { accessToken, refreshToken } = await authService.generateTokenPair(
    user.id
  );

  // ... rest of login flow
});

// 5. Protected Route with Middleware
const authenticate = async (req, res, next) => {
  try {
    // Check for token in Authorization header
    const authHeader = req.headers.authorization;
    if (!authHeader?.startsWith("Bearer ")) {
      return res.status(401).json({ error: "No token provided" });
    }

    const token = authHeader.split(" ")[1];

    // Verify token
    const decoded = jwt.verify(token, process.env.JWT_SECRET);

    // Check token type
    if (decoded.type !== "access") {
      return res.status(401).json({ error: "Invalid token type" });
    }

    // Check if token is blacklisted
    if (await authService.isTokenBlacklisted(token)) {
      return res.status(401).json({ error: "Token revoked" });
    }

    // Get user from database
    const user = await db.users.findOne({ id: decoded.sub });
    if (!user) {
      return res.status(401).json({ error: "User not found" });
    }

    // Check if user is active
    if (!user.active) {
      return res.status(403).json({ error: "Account deactivated" });
    }

    // Add user to request
    req.user = user;
    next();
  } catch (error) {
    if (error.name === "TokenExpiredError") {
      return res.status(401).json({
        error: "Token expired",
        code: "TOKEN_EXPIRED",
      });
    }
    if (error.name === "JsonWebTokenError") {
      return res.status(403).json({ error: "Invalid token" });
    }
    next(error);
  }
};

// 6. Use protected routes
app.get("/api/user/profile", authenticate, (req, res) => {
  res.json({
    id: req.user.id,
    email: req.user.email,
    name: req.user.name,
    createdAt: req.user.createdAt,
  });
});

// 7. Refresh token endpoint
app.post("/refresh-token", async (req, res) => {
  const refreshToken = req.cookies.refreshToken;

  if (!refreshToken) {
    return res.status(401).json({ error: "No refresh token" });
  }

  try {
    const { accessToken } = await authService.refreshAccessToken(refreshToken);
    res.json({ accessToken });
  } catch (error) {
    // Clear invalid refresh token cookie
    res.clearCookie("refreshToken");
    res.status(401).json({ error: "Session expired, please login again" });
  }
});

// 8. Logout
app.post("/logout", authenticate, async (req, res) => {
  const refreshToken = req.cookies.refreshToken;

  if (refreshToken) {
    await authService.logout(req.user.id, refreshToken);
    res.clearCookie("refreshToken");
  }

  // Optionally blacklist the current access token
  const accessToken = req.headers.authorization?.split(" ")[1];
  if (accessToken) {
    await authService.blacklistToken(accessToken);
  }

  res.json({ message: "Logged out successfully" });
});
```

---

## 📊 **Authentication Best Practices Summary**

### **DOs:**

```javascript
// ✅ DO THESE:

// 1. Use HTTPS everywhere
// 2. Hash passwords with bcrypt/scrypt/argon2
// 3. Use short-lived access tokens (15-60 minutes)
// 4. Store refresh tokens securely (HTTP-only cookies)
// 5. Implement rate limiting on auth endpoints
// 6. Validate and sanitize all inputs
// 7. Use secure, random JWT secrets (256-bit+)
// 8. Implement proper error messages (don't reveal too much)
// 9. Log security events
// 10. Regularly rotate secrets
```

### **DON'Ts:**

```javascript
// ❌ DON'T DO THESE:

// 1. Don't use Basic Auth in production
// 2. Don't store passwords in plain text
// 3. Don't use weak password requirements
// 4. Don't put sensitive data in JWTs
// 5. Don't use JWT for sessions without careful consideration
// 6. Don't skip email verification for user accounts
// 7. Don't expose detailed error messages
// 8. Don't forget to invalidate tokens on logout
// 9. Don't use predictable token generation
// 10. Don't skip security headers (CSP, HSTS, etc.)
```

### **Security Headers for Authentication**

```javascript
// Essential security headers
app.use((req, res, next) => {
  res.setHeader("X-Content-Type-Options", "nosniff");
  res.setHeader("X-Frame-Options", "DENY");
  res.setHeader("X-XSS-Protection", "1; mode=block");
  res.setHeader("Referrer-Policy", "strict-origin-when-cross-origin");
  res.setHeader("Permissions-Policy", "geolocation=(), microphone=()");
  next();
});
```

---

## 🚀 **Production Checklist**

### **Before Launch:**

```markdown
- [ ] All auth endpoints behind HTTPS
- [ ] Password hashing implemented (bcrypt/argon2)
- [ ] Rate limiting on login/register endpoints
- [ ] Email verification required
- [ ] JWT secrets rotated from development
- [ ] CORS properly configured
- [ ] Security headers set
- [ ] Logging for auth events
- [ ] Session invalidation on logout
- [ ] Refresh token storage secure
```

### **Monitoring:**

```javascript
// Monitor these metrics:
- Failed login attempts per IP
- Account lockouts
- Token refresh rates
- Unusual geographic logins
- Multiple devices per user
- Stale/unused accounts
```

### **Incident Response:**

```javascript
// If breach suspected:
1. Force password resets for affected users
2. Invalidate all sessions
3. Review access logs
4. Check for unusual patterns
5. Update compromised secrets
6. Notify affected users
```

---

## 🎯 **Choosing Your Authentication Strategy**

### **Simple App (Startup MVP)**

```javascript
// Start with:
1. Email/password registration
2. JWT tokens (access + refresh)
3. Email verification
4. Basic rate limiting
```

### **SaaS Application**

```javascript
// Add:
1. OAuth 2.0 (Google, GitHub, etc.)
2. Multi-factor authentication
3. Session management dashboard
4. Audit logging
5. Role-based access control
```

### **Enterprise Application**

```javascript
// Add:
1. SAML/SSO integration
2. LDAP/Active Directory
3. Compliance logging
4. Advanced threat detection
5. Regular security audits
```

---

> **Remember**: Authentication is your front door. Make it strong enough to keep attackers out, but convenient enough for legitimate users. Start simple, secure it properly, and add complexity only when needed.

**Your next step**: Implement the login flow with access/refresh tokens. Test it thoroughly, then add one security feature at a time (rate limiting, then MFA, then audit logging). Security is a journey, not a destination. 🔐
