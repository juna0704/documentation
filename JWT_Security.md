# 🧠 **JWT & AUTHENTICATION - CRAM SHEET**

## 🎯 **CORE PRINCIPLES**

### **1. JWT STRUCTURE (3 PARTS)**

```
Header.Alg+Type    Payload.Data     Signature.Verify
----------         ------------     ------------
{                  {                 HMACSHA256(
  "alg": "HS256",    "userId": "123",   base64UrlEncode(header) + "." +
  "typ": "JWT"       "exp": 1516239022  base64UrlEncode(payload),
}                  }                 secret)
```

### **2. TWO TOKEN STRATEGY**

```
ACCESS TOKEN (15min):
- Short-lived (15-30 minutes)
- Sent in Authorization header
- Contains user data (userId, role)
- Stored in MEMORY (not localStorage!)

REFRESH TOKEN (7 days):
- Long-lived (7 days)
- HTTP-only, Secure, SameSite cookie
- Used ONLY for getting new access tokens
- Can be revoked/rotated
```

---

## 🔄 **COMPLETE FLOW - 9 STEPS**

```
1. 📝 REGISTER: User → Email/Password → Argon2 hash → DB
2. 📧 VERIFY: Send verification email with JWT token (24h)
3. 🔑 LOGIN: Email+Password → Verify → Generate tokens
4. 🍪 SET COOKIE: Refresh token → HTTP-only cookie
5. 📱 STORE: Access token → React state/memory
6. 📤 REQUEST: Header: Authorization: Bearer <token>
7. 🛡️ VERIFY: Backend checks token → Attaches user to req
8. 🔄 REFRESH: Token expires → Use refresh token → Get new
9. 🚪 LOGOUT: Clear tokens + Revoke refresh token
```

---

## 🛡️ **SECURITY RULES - MUST FOLLOW!**

### **TOKEN STORAGE RULES:**

```
✅ DO (SAFE):
- Access token: Memory/React state
- Refresh token: HTTP-only cookie
- User info: localStorage (non-sensitive)

❌ DON'T (UNSAFE):
- Access token in localStorage ❌ (XSS risk!)
- Tokens in sessionStorage ❌ (still XSS)
- Sensitive data in localStorage ❌
```

### **COOKIE SETTINGS (Must Have):**

```javascript
res.cookie("refreshToken", token, {
  httpOnly: true, // No JavaScript access
  secure: true, // HTTPS only
  sameSite: "strict", // Prevent CSRF
  path: "/api/auth/refresh", // Only sent to refresh endpoint
  maxAge: 7 * 24 * 60 * 60 * 1000, // 7 days
});
```

---

## 💰 **WHY REFRESH TOKENS?**

### **Without Refresh Tokens:**

```
Token expires in 15min → User logs in again → Bad UX
```

### **With Refresh Tokens:**

```
Access token (15min) + Refresh token (7 days)
↓
Access expires → Use refresh token → Get new access
↓
User stays logged in for 7 days ✅
```

### **Security Benefits:**

1. **Short-lived access tokens** = Less damage if stolen
2. **Can revoke refresh tokens** = Immediate logout
3. **Token rotation** = Detect theft
4. **Reduced database hits** = Better performance

---

## 🔐 **AUTHENTICATION MIDDLEWARE - WHAT IT DOES**

```typescript
// 1. Get token from: Authorization: Bearer <token>
// 2. Verify JWT signature
// 3. Check expiry (exp claim)
// 4. Optional: Check blacklist (Redis)
// 5. Get user from DB (optional)
// 6. Attach to request: req.user = { userId, email, role }
// 7. Check user status (locked, verified)
```

**Key Check: `userId` in EVERY database query!**

```typescript
// ALWAYS do this:
await prisma.trade.findMany({
  where: { userId: req.user.userId }, // ← MUST BE HERE
});
```

---

## 📊 **OPTIONS COMPARISON**

### **LocalStorage vs Cookies:**

|                | LocalStorage | HTTP-only Cookies |
| -------------- | ------------ | ----------------- |
| **XSS Safe**   | ❌ No        | ✅ Yes            |
| **CSRF Safe**  | ✅ Yes       | ⚠️ Needs SameSite |
| **Auto-sent**  | ❌ No        | ✅ Yes            |
| **Size Limit** | 5MB          | 4KB               |

### **Session vs JWT:**

|                      | Sessions         | JWT                |
| -------------------- | ---------------- | ------------------ |
| **Stateless**        | ❌ No            | ✅ Yes             |
| **Immediate Revoke** | ✅ Yes           | ❌ Needs blacklist |
| **Scalability**      | ⚠️ Needs Redis   | ✅ Excellent       |
| **Mobile Friendly**  | ⚠️ Cookie issues | ✅ Yes             |

---

## 🚀 **BEST PRACTICES SUMMARY**

### **1. STORAGE:**

- **Access token**: Memory/React state
- **Refresh token**: HTTP-only cookie
- **User data**: localStorage (non-sensitive only)

### **2. SECURITY:**

- **Password hashing**: Argon2 > bcrypt > SHA
- **Input validation**: Zod on ALL endpoints
- **Rate limiting**: Per user, per endpoint
- **HTTPS**: Always in production

### **3. TOKENS:**

- **Access**: 15-30 minutes expiry
- **Refresh**: 7 days expiry, rotate on use
- **Claims**: Include userId, role, tokenType
- **Secrets**: Different for access/refresh tokens

### **4. VALIDATION:**

- **Backend**: Always validate even if frontend did
- **User isolation**: `userId` in every query
- **Error messages**: Generic (no info leakage)

---

## 🎯 **INTERVIEW ANSWERS - QUICK RECALL**

### **Q: Why not store JWT in localStorage?**

> "LocalStorage is vulnerable to XSS attacks. If malicious JavaScript runs on the page, it can steal tokens. HTTP-only cookies are safer because JavaScript can't access them."

### **Q: Why refresh tokens?**

> "Refresh tokens allow short-lived access tokens (15min) for security while maintaining good UX. If an access token is stolen, it's only valid for 15 minutes. Refresh tokens can be revoked immediately."

### **Q: How do you prevent CSRF?**

> "SameSite cookies prevent most CSRF. For extra security, we use CSRF tokens: backend sets HTTP-only cookie, frontend reads and sends in header for state-changing requests."

### **Q: How to handle token expiration?**

> "Axios interceptors catch 401 errors, automatically refresh token using refresh token cookie, then retry request. User stays logged in seamlessly."

### **Q: How to implement logout?**

> "1. Remove access token from memory. 2. Clear refresh token cookie. 3. Revoke refresh token in database. 4. Optional: Add access token to Redis blacklist."

---

## ⚠️ **COMMON MISTAKES TO AVOID**

1. **Storing tokens in localStorage** ❌
2. **Not validating tokens on backend** ❌
3. **No rate limiting on auth endpoints** ❌
4. **Revealing if user exists in error messages** ❌
5. **Using JWT for sessions without expiry** ❌
6. **Same secret for access and refresh tokens** ❌
7. **No input validation** ❌
8. **Missing userId in queries** ❌

---

## 📝 **IMPLEMENTATION CHECKLIST**

### **Backend:**

- [ ] Argon2 password hashing
- [ ] Zod input validation
- [ ] JWT token generation
- [ ] HTTP-only cookie setup
- [ ] Authentication middleware
- [ ] Refresh token endpoint
- [ ] Token blacklisting (Redis)
- [ ] Rate limiting
- [ ] Security headers (Helmet)

### **Frontend:**

- [ ] Token in memory (not localStorage)
- [ ] Axios interceptors for 401
- [ ] Auto-refresh before expiry
- [ ] Secure cookie handling
- [ ] Logout cleanup
- [ ] Protected routes

---

## 🔄 **REFRESH FLOW - SIMPLE VERSION**

```
1. Access token expires
2. Frontend gets 401 error
3. Axios interceptor catches it
4. Sends refresh request (cookie auto-sent)
5. Backend verifies refresh token
6. Issues new access token
7. Frontend retries original request
```

**Time**: User never notices!

---

## 🎓 **KEY TAKEAWAYS - MEMORIZE THESE!**

### **3 MUST-DO'S:**

1. **User isolation**: `WHERE userId = ?` in EVERY query
2. **Token security**: Access in memory, refresh in HTTP-only cookie
3. **Input validation**: Zod on ALL endpoints, front & back

### **2 FORMULAS:**

1. **Password hash**: Argon2 > bcrypt > anything else
2. **Token expiry**: Access=15min, Refresh=7days

### **1 GOLDEN RULE:**

**"Never trust the client. Validate everything on the backend."**

---

## 🚨 **RED FLAGS IN CODE REVIEW**

```typescript
// ❌ BAD - Token in localStorage
localStorage.setItem("token", jwt);

// ❌ BAD - No userId filter
prisma.trades.findMany({ where: {} });

// ❌ BAD - No input validation
app.post("/api/trades", (req, res) => {
  const data = req.body; // No validation!
});

// ❌ BAD - Revealing user existence
if (!user) return "User not found"; // Bad!
// ✅ GOOD
if (!user) return "Invalid credentials"; // Generic
```

---

## ✅ **SECURITY SCORECARD**

**Basic Security (Must Have):**

- HTTPS: ✅
- Password hash (Argon2/bcrypt): ✅
- Input validation: ✅
- User isolation: ✅
- Rate limiting: ✅

**Good Security (Should Have):**

- Refresh tokens: ✅
- HTTP-only cookies: ✅
- CSRF protection: ✅
- Security headers: ✅
- Logging: ✅

**Advanced Security (Nice to Have):**

- 2FA/MFA: ⚠️
- Device fingerprinting: ⚠️
- Anomaly detection: ⚠️
- Penetration testing: ⚠️

---

## 🧩 **MENTAL MODEL FOR AUTH**

### **Think of it like:**

- **Access token** = Day pass to amusement park (expires today)
- **Refresh token** = Season pass (long-term, can be revoked)
- **HTTP-only cookie** = Locked safe (JavaScript can't steal)
- **userId filter** = Personal locker (only you have the key)

### **When in doubt:**

1. Where's the token stored? (Memory > localStorage)
2. Is userId in the query? (Always!)
3. Is input validated? (Zod everywhere)
4. Is HTTPS on? (Always in production)

---

## 🎤 **ELEVATOR PITCH FOR INTERVIEW**

> "I implemented a secure JWT authentication system with short-lived access tokens stored in memory and long-lived refresh tokens in HTTP-only cookies. Every database query filters by userId for complete user isolation. I use Zod for validation, Argon2 for password hashing, and rate limiting on all auth endpoints. The system automatically refreshes tokens before expiry, providing both security and good user experience."

---

## 💡 **REMEMBER THIS MNEMONIC**

**S.A.F.E. Authentication:**

- **S**hort-lived access tokens (15min)
- **A**ccess tokens in memory
- **F**ilter by userId (every query!)
- **E**very input validated (front & back)

---

**YOU'VE GOT THIS!** 🚀 Just remember: **Memory tokens, HTTP-only cookies, userId everywhere!**
