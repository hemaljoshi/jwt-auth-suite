# JWT Auth Suite 🔐

A comprehensive JWT authentication helper library with TypeScript support, designed to make JWT-based authentication simple and powerful for Node.js applications.

## 📚 Table of Contents

- [Features](#features)
- [Installation](#installation)
- [Getting Started (5 Minutes)](#getting-started-5-minutes)
- [Quick Start](#quick-start)
- [initAuth vs createAuth](#initauth-vs-createauth)
- [Using Rate Limiting with Authentication](#using-rate-limiting-with-authentication)
- [Configuration](#configuration)
- [API Reference](#api-reference)
- [Framework Integrations](#framework-integrations)
- [Advanced Features](#advanced-features)
- [Security Best Practices](#security-best-practices)
- [Performance & Scalability](#performance--scalability)
- [Troubleshooting](#troubleshooting)
- [Quick Reference](#quick-reference)
- [FAQ](#faq)
- [Roadmap](#roadmap)
- [Contributing](#contributing)
- [License](#license)

## Features

- ✅ **Token Management** - Generate and verify access/refresh tokens
- ✅ **Route Protection** - Middleware for protecting Express routes
- ✅ **Role-Based Access Control** - Simple role and permission system
- ✅ **JWT Blacklisting** - Secure logout with token invalidation
- ✅ **Password Hashing** - Built-in bcrypt password utilities
- ✅ **Multi-Tenant Support** - SaaS-ready tenant isolation
- ✅ **Refresh Token Rotation** - Enhanced security with automatic token rotation
- ✅ **TypeScript Support** - Full TypeScript support with dual JS/TS compatibility
- ✅ **Flexible Configuration** - Customizable expiry times, algorithms, and storage
- ✅ **Error Handling** - Standardized error responses
- ✅ **Express Integration** - Seamless Express.js middleware
- ✅ **Rate Limiting** - Built-in rate limiting for authentication endpoints
- ✅ **Security Logging** - Comprehensive security event logging and monitoring
- ✅ **Metrics Collection** - Performance monitoring and analytics
- ✅ **Production Ready** - Enterprise-grade security and monitoring features

## Installation

```bash
npm install jwt-auth-suite
```

## Getting Started (5 Minutes)

### Step 1: Install the Package

```bash
npm install jwt-auth-suite
```

### Step 2: Basic Setup

```javascript
const { initAuth } = require("jwt-auth-suite");

const auth = initAuth({
  secret: "your-secret-key-here", // Use a strong secret in production
  roles: ["admin", "user"],
  permissions: ["read", "write"],
});
```

### Step 3: Protect a Route

```javascript
const express = require("express");
const app = express();

// Protect any route
app.get("/profile", auth.protect(), (req, res) => {
  res.json({ user: req.user });
});

app.listen(3000, () => {
  console.log("🚀 Server running on http://localhost:3000");
});
```

### Step 4: Test It

```bash
# Start your server
node app.js

# Test the protected route (will fail without token)
curl http://localhost:3000/profile

# Test with a token
curl -H "Authorization: Bearer YOUR_TOKEN" http://localhost:3000/profile
```

**🎉 That's it! You now have JWT authentication working!**

> **Next Steps:** Check out the [Configuration](#configuration) section to customize your setup, or jump to [Production Features](#production-features) for advanced features.

## Quick Start

### Basic Authentication (initAuth)

```javascript
const { initAuth } = require("jwt-auth-suite");
// or
import { initAuth } from "jwt-auth-suite";

const auth = initAuth({
  secret: process.env.JWT_SECRET,
  accessExpiry: "15m",
  refreshExpiry: "7d",
  roles: ["admin", "user"],
  permissions: ["read", "write"],
  storage: "header", // or 'cookie'
});

// Protect a route
app.get("/profile", auth.protect(), (req, res) => {
  res.json({ user: req.user });
});
```

### Production Authentication (createAuth)

```javascript
const { createAuth } = require("jwt-auth-suite");

const auth = createAuth({
  secret: process.env.JWT_SECRET,
  accessExpiry: "15m",
  refreshExpiry: "7d",
  roles: ["admin", "user"],
  permissions: ["read", "write"],

  // Production features
  enableRateLimiting: true,
  enableSecurityLogging: true,
  enableMetrics: true,
  enableTenants: true,
  enableRefreshRotation: true,
});

// Protect a route with rate limiting
app.get(
  "/profile",
  auth.rateLimiter.api.createMiddleware(), // Rate limiting
  auth.protect(), // Authentication
  (req, res) => {
    res.json({ user: req.user });
  }
);
```

## Quick Reference: Roles & Permissions

**Roles** are assigned during user registration:

```javascript
// Registration with role
app.post("/register", (req, res) => {
  const { email, password, role = "user" } = req.body;
  const permissions = getPermissionsForRole(role);
  // Store user with role and permissions...
});
```

**Permissions** are derived from roles:

```javascript
function getPermissionsForRole(role) {
  return (
    {
      admin: ["read", "write", "delete", "manage_users"],
      user: ["read", "write"],
    }[role] || ["read"]
  );
}
```

**Route Protection**:

```javascript
app.get("/admin", auth.requireRole("admin"), handler); // Role-based
app.get("/posts", auth.requirePermission("read"), handler); // Permission-based
app.get(
  "/both",
  auth.protect({ roles: ["admin"], permissions: ["write"] }),
  handler
); // Both
```

## initAuth vs createAuth

### Understanding the Difference

JWT Auth Suite provides two main functions for different use cases:

| Feature                    | initAuth | createAuth |
| -------------------------- | -------- | ---------- |
| **Basic JWT**              | ✅       | ✅         |
| **Route Protection**       | ✅       | ✅         |
| **Role/Permission Checks** | ✅       | ✅         |
| **Rate Limiting**          | ❌       | ✅         |
| **Security Logging**       | ❌       | ✅         |
| **Metrics Collection**     | ❌       | ✅         |
| **Token Blacklisting**     | ❌       | ✅         |
| **Password Hashing**       | ❌       | ✅         |
| **Multi-tenant Support**   | ❌       | ✅         |
| **Refresh Token Rotation** | ❌       | ✅         |
| **Production Ready**       | ❌       | ✅         |

### When to Use initAuth

Use `initAuth` for:

- ✅ **Simple applications** - Basic JWT authentication
- ✅ **Learning/Prototyping** - Quick setup without complexity
- ✅ **MVP development** - Minimal viable product
- ✅ **Small projects** - Don't need production features

```javascript
const { initAuth } = require("jwt-auth-suite");

const auth = initAuth({
  secret: process.env.JWT_SECRET,
  roles: ["admin", "user"],
  permissions: ["read", "write"],
});

// Basic usage
app.get("/profile", auth.protect(), (req, res) => {
  res.json({ user: req.user });
});
```

### When to Use createAuth

Use `createAuth` for:

- ✅ **Production applications** - Full-featured authentication
- ✅ **Enterprise apps** - Need security monitoring
- ✅ **SaaS platforms** - Multi-tenant support
- ✅ **High-traffic apps** - Rate limiting required
- ✅ **Compliance needs** - Security logging required

```javascript
const { createAuth } = require("jwt-auth-suite");

const auth = createAuth({
  secret: process.env.JWT_SECRET,
  roles: ["admin", "user"],
  permissions: ["read", "write"],

  // Production features
  enableRateLimiting: true,
  enableSecurityLogging: true,
  enableMetrics: true,
  enableTenants: true,
  enableRefreshRotation: true,
});

// Advanced usage with rate limiting
app.get(
  "/admin",
  auth.rateLimiter.api.createMiddleware(),
  auth.requireRole("admin"),
  (req, res) => {
    res.json({ message: "Admin panel" });
  }
);
```

### Migration from initAuth to createAuth

You can easily upgrade from `initAuth` to `createAuth` without changing existing code:

```javascript
// Before (initAuth)
const auth = initAuth({
  secret: process.env.JWT_SECRET,
  roles: ["admin", "user"],
});

// After (createAuth) - just add production features
const auth = createAuth({
  secret: process.env.JWT_SECRET,
  roles: ["admin", "user"],

  // Add production features
  enableRateLimiting: true,
  enableSecurityLogging: true,
  enableMetrics: true,
});

// All existing code still works!
app.get("/profile", auth.protect(), (req, res) => {
  res.json({ user: req.user });
});
```

## Using Rate Limiting with Authentication

### Method 1: Middleware Stack (Recommended)

```javascript
// Apply rate limiting first, then authentication
app.post(
  "/login",
  auth.rateLimiter.login.createMiddleware(), // 1. Rate limiting
  auth.protect(), // 2. Authentication
  (req, res) => {
    res.json({ message: "Access granted!" });
  }
);
```

### Method 2: Custom Combined Middleware

```javascript
// Create a combined middleware
const rateLimitedAuth = (req, res, next) => {
  // First apply rate limiting
  auth.rateLimiter.login.createMiddleware()(req, res, (err) => {
    if (err) return next(err);

    // Then apply authentication
    auth.protect()(req, res, next);
  });
};

// Use the combined middleware
app.post("/admin-panel", rateLimitedAuth, (req, res) => {
  res.json({ message: "Admin panel accessed!" });
});
```

### Method 3: Express Router with Multiple Middlewares

```javascript
const router = express.Router();

// Apply rate limiting to all routes in this router
router.use(auth.rateLimiter.api.createMiddleware());

// Then add authentication to specific routes
router.get("/profile", auth.protect(), (req, res) => {
  res.json({ user: req.user });
});

router.get("/admin", auth.requireRole("admin"), (req, res) => {
  res.json({ message: "Admin only!" });
});

app.use("/api", router);
```

### Complete Example: Rate Limiting + Auth Protection

```javascript
const express = require("express");
const { createAuth } = require("jwt-auth-suite");

const app = express();
app.use(express.json());

// Initialize with all features
const auth = createAuth({
  secret: process.env.JWT_SECRET,
  roles: ["admin", "user", "moderator"],
  permissions: ["read", "write", "delete", "manage_users"],

  // Enable production features
  enableRateLimiting: true,
  enableSecurityLogging: true,
  enableMetrics: true,

  // Rate limiting configuration
  rateLimitStorage: "memory", // or 'redis'

  // Security logging configuration
  securityLoggerConfig: {
    enableConsoleLogging: true,
    logLevel: "MEDIUM",
  },

  // Metrics configuration
  metricsConfig: {
    enableConsoleMetrics: true,
    collectionInterval: 60000,
  },
});

// Apply security middleware globally
app.use(auth.securityLogger.createMiddleware());
app.use(auth.metrics.createRequestMetricsMiddleware());

// 1. Public route with rate limiting only
app.post(
  "/login",
  auth.rateLimiter.login.createMiddleware(), // 5 attempts per 15 minutes
  (req, res) => {
    const { email, password } = req.body;

    // Simulate authentication
    if (email === "admin@test.com" && password === "admin123") {
      const token = auth.generateToken({
        sub: "user123",
        email: "admin@test.com",
        role: "admin",
        permissions: ["read", "write", "delete", "manage_users"],
      });

      // Log successful login
      auth.securityLogger.logAuthSuccess("user123", req, {
        method: "password",
      });
      auth.metrics.recordAuthSuccess("user123", "password");

      res.json({ token });
    } else {
      // Log failed login
      auth.securityLogger.logAuthFailure(req, "Invalid credentials");
      auth.metrics.recordAuthFailure("password", "Invalid credentials");

      res.status(401).json({ error: "Invalid credentials" });
    }
  }
);

// 2. Protected route with rate limiting + authentication
app.get(
  "/profile",
  auth.rateLimiter.api.createMiddleware(), // 100 requests per 15 minutes
  auth.protect(), // Require valid token
  (req, res) => {
    res.json({
      message: "Profile accessed!",
      user: req.user,
    });
  }
);

// 3. Admin route with rate limiting + authentication + role check
app.get(
  "/admin-panel",
  auth.rateLimiter.api.createMiddleware(), // 100 requests per 15 minutes
  auth.requireRole("admin"), // Require admin role
  (req, res) => {
    res.json({
      message: "Admin panel accessed!",
      user: req.user,
    });
  }
);

// 4. Sensitive route with custom rate limiting
app.post(
  "/change-password",
  auth.rateLimiter.passwordReset.createMiddleware(), // 3 attempts per hour
  auth.protect(), // Require valid token
  (req, res) => {
    res.json({ message: "Password changed!" });
  }
);

// 5. Logout with token blacklisting
app.post(
  "/logout",
  auth.rateLimiter.api.createMiddleware(), // 100 requests per 15 minutes
  auth.protect(), // Require valid token
  async (req, res) => {
    const token = auth.extractToken(req);
    await auth.blacklistToken(token);

    // Log logout
    auth.securityLogger.logTokenBlacklisted(req.user.id, req, "logout");
    auth.metrics.recordTokenBlacklisted("access", req.user.id);

    res.json({ message: "Logged out successfully" });
  }
);

app.listen(3000, () => {
  console.log("🚀 Server running with rate limiting + auth protection!");
});
```

### Middleware Order Best Practices

**Important**: The order of middleware matters! Here's the recommended order:

```javascript
// ✅ CORRECT ORDER
app.use(express.json()); // 1. Parse JSON
app.use(auth.securityLogger.createMiddleware()); // 2. Security logging
app.use(auth.metrics.createRequestMetricsMiddleware()); // 3. Metrics collection
app.use(auth.rateLimiter.api.createMiddleware()); // 4. Rate limiting
app.use(auth.protect()); // 5. Authentication
app.use(auth.requireRole("admin")); // 6. Authorization
// Your route handler

// ❌ WRONG ORDER - Rate limiting after auth means authenticated users bypass rate limits
app.use(auth.protect()); // 1. Authentication
app.use(auth.rateLimiter.api.createMiddleware()); // 2. Rate limiting (too late!)
```

### Common Middleware Patterns

```javascript
// Pattern 1: Public routes with rate limiting only
app.post("/login", auth.rateLimiter.login.createMiddleware(), (req, res) => {
  /* login logic */
});

// Pattern 2: Protected routes with rate limiting + auth
app.get(
  "/profile",
  auth.rateLimiter.api.createMiddleware(),
  auth.protect(),
  (req, res) => {
    /* profile logic */
  }
);

// Pattern 3: Admin routes with rate limiting + auth + role
app.get(
  "/admin",
  auth.rateLimiter.api.createMiddleware(),
  auth.requireRole("admin"),
  (req, res) => {
    /* admin logic */
  }
);

// Pattern 4: Sensitive routes with custom rate limiting
app.post(
  "/change-password",
  auth.rateLimiter.passwordReset.createMiddleware(),
  auth.protect(),
  (req, res) => {
    /* password change logic */
  }
);

// Pattern 5: Multiple middleware with error handling
app.post(
  "/sensitive-action",
  auth.rateLimiter.api.createMiddleware(),
  auth.protect(),
  auth.requirePermission("write"),
  (req, res) => {
    /* sensitive action logic */
  }
);
```

## Configuration

### Basic Configuration

```javascript
const auth = initAuth({
  secret: "your-secret-key", // Required: JWT secret (min 32 chars)
  accessExpiry: "15m", // Access token expiry (default: '15m')
  refreshExpiry: "7d", // Refresh token expiry (default: '7d')
  algorithm: "HS256", // JWT algorithm (default: 'HS256')
  storage: "header", // Token storage: 'header' or 'cookie'
  roles: ["admin", "user"], // Available roles
  permissions: ["read", "write"], // Available permissions
  cookieName: "access_token", // Cookie name (for cookie storage)
  cookieOptions: {
    // Cookie options
    httpOnly: true,
    secure: false,
    sameSite: "lax",
  },
});
```

### Advanced Configuration

```javascript
const auth = createAuth({
  // Basic JWT settings
  secret: process.env.JWT_SECRET,
  accessExpiry: "15m",
  refreshExpiry: "7d",

  // JWT Blacklisting
  blacklistStorage: "redis", // 'memory', 'redis', or 'database'
  redisClient: redisClient, // Redis client instance

  // Password Hashing
  passwordSaltRounds: 12, // bcrypt salt rounds (default: 12)

  // Multi-Tenant Support
  enableTenants: true, // Enable tenant isolation

  // Refresh Token Rotation
  enableRefreshRotation: true, // Enable automatic token rotation

  // Database Integration
  dbClient: dbClient, // Database client for persistent storage
});
```

## How Roles & Permissions Work

### Understanding the System

JWT Auth Suite uses a **role-based access control (RBAC)** system where:

1. **Roles** are broad categories (e.g., `admin`, `moderator`, `user`)
2. **Permissions** are specific actions (e.g., `read`, `write`, `delete`, `manage_users`)
3. **Users** are assigned roles, and roles determine permissions

### Role Assignment

Roles are typically assigned during user registration or creation:

```javascript
// Registration endpoint
app.post('/register', (req, res) => {
  const { email, password, role = 'user' } = req.body; // Default to 'user'

  // Validate role
  const allowedRoles = ['admin', 'moderator', 'user'];
  if (!allowedRoles.includes(role)) {
    return res.status(400).json({ error: 'Invalid role' });
  }

  // Get permissions based on role
  const permissions = getPermissionsForRole(role);

  // Store user with role and permissions
  const user = {
    email,
    password: await bcrypt.hash(password, 10),
    role: role,
    permissions: permissions
  };

  // Save to database...
});

// Helper function to assign permissions based on role
function getPermissionsForRole(role) {
  const rolePermissions = {
    'admin': ['read', 'write', 'delete', 'manage_users', 'manage_settings'],
    'moderator': ['read', 'write', 'delete'],
    'user': ['read', 'write'],
    'guest': ['read']
  };

  return rolePermissions[role] || ['read'];
}
```

### Different Registration Scenarios

**Self-Registration (Default Role)**

```javascript
// New users always get 'user' role
const { email, password } = req.body;
const role = "user"; // Always 'user' for self-registration
```

**Admin-Created Users**

```javascript
// Admin can assign any role
app.post("/admin/create-user", auth.requireRole("admin"), (req, res) => {
  const { email, password, role } = req.body;
  // Admin chooses the role: 'admin', 'moderator', 'user'
});
```

**Invitation-Based Registration**

```javascript
// User gets role from invitation
app.post("/complete-registration", (req, res) => {
  const { invitationToken, password } = req.body;

  const invitation = getInvitationByToken(invitationToken);
  const role = invitation.role; // Role comes from invitation
});
```

### Database Structure

```sql
-- Users table with roles
CREATE TABLE users (
  id INT PRIMARY KEY,
  email VARCHAR(255) UNIQUE,
  password_hash VARCHAR(255),
  role VARCHAR(50) DEFAULT 'user',  -- Role stored here
  created_at TIMESTAMP
);

-- Example data
INSERT INTO users (email, password_hash, role) VALUES
('admin@company.com', '$2b$10$...', 'admin'),
('user@company.com', '$2b$10$...', 'user');
```

### Access Control Matrix

| Route                 | Admin | Moderator | User | Guest |
| --------------------- | ----- | --------- | ---- | ----- |
| `/profile`            | ✅    | ✅        | ✅   | ❌    |
| `/admin-panel`        | ✅    | ❌        | ❌   | ❌    |
| `/posts` (GET)        | ✅    | ✅        | ✅   | ❌    |
| `/posts` (POST)       | ✅    | ✅        | ✅   | ❌    |
| `/posts/:id` (DELETE) | ✅    | ✅        | ❌   | ❌    |
| `/users`              | ✅    | ❌        | ❌   | ❌    |

## API Reference

### Token Management

```javascript
// Generate access token with user data
const token = auth.generateToken({
  sub: "user123",
  email: "user@example.com",
  role: "admin",
  permissions: ["read", "write", "delete", "manage_users"],
});

// Verify token
const payload = auth.verifyToken(token);
// payload contains: { sub, email, role, permissions, iat, exp }

// Extract token from request
const token = auth.extractToken(req);
```

### Route Protection

```javascript
// Basic protection (requires valid token)
app.get("/protected", auth.protect(), (req, res) => {
  res.json({ user: req.user });
});

// Role-based protection
app.get("/admin", auth.requireRole("admin"), (req, res) => {
  res.json({ message: "Admin only" });
});

// Permission-based protection
app.get("/posts", auth.requirePermission("read"), (req, res) => {
  res.json({ posts: [] });
});

// Multiple roles/permissions
app.get(
  "/management",
  auth.protect({
    roles: ["admin", "moderator"],
    permissions: ["manage"],
  }),
  (req, res) => {
    res.json({ message: "Management panel" });
  }
);

// Optional authentication (doesn't fail if no token)
app.get("/public", auth.optional(), (req, res) => {
  if (req.user) {
    res.json({ message: "Welcome back!", user: req.user });
  } else {
    res.json({ message: "Welcome, guest!" });
  }
});
```

### Advanced Usage

```javascript
const { createAuth } = require("jwt-auth-suite");

const auth = createAuth(config);

// Generate token pair
const { accessToken, refreshToken } = auth.generateTokenPair({
  sub: "user123",
  role: "admin",
});

// Check if token is expired
const isExpired = auth.isTokenExpired(token);

// Get token expiry date
const expiry = auth.getTokenExpiry(token);

// Role checking utilities
const hasRole = auth.hasRole(user, "admin");
const hasPermission = auth.hasPermission(user, "write");
const isAdmin = auth.isAdmin(user);
```

## Error Handling

JWT Auth Suite provides standardized error responses:

```javascript
// Error response format
{
  "error": {
    "code": "TOKEN_MISSING",
    "message": "Access token is missing",
    "statusCode": 401
  }
}
```

### Error Codes

- `TOKEN_MISSING` - No token provided
- `TOKEN_INVALID` - Invalid token format/signature
- `TOKEN_EXPIRED` - Token has expired
- `INSUFFICIENT_PERMISSIONS` - User lacks required permissions
- `INVALID_ROLE` - User lacks required role
- `CONFIG_ERROR` - Configuration error

## TypeScript Support

```typescript
import {
  initAuth,
  createAuth,
  AuthConfig,
  User,
  JWTPayload,
  ErrorMessageKeys,
} from "jwt-auth-suite";

const config: AuthConfig = {
  secret: process.env.JWT_SECRET!,
  accessExpiry: "15m",
  roles: ["admin", "user"],
};

const auth = initAuth(config);

// req.user is properly typed
app.get("/profile", auth.protect(), (req, res) => {
  const user: User = req.user!; // TypeScript knows this is a User
  res.json({ user });
});

// ErrorMessageKeys enum provides full type safety
const authAdvanced = createAuth({
  secret: process.env.JWT_SECRET!,
  roles: ["admin", "user"],
  errorMessages: {
    [ErrorMessageKeys.INVALID_TOKEN]: "Custom invalid token message",
    [ErrorMessageKeys.UNAUTHORIZED]: "Custom unauthorized message",
    [ErrorMessageKeys.FORBIDDEN]: "Custom forbidden message",
    [ErrorMessageKeys.NOT_FOUND]: "Custom not found message",
    [ErrorMessageKeys.INTERNAL_ERROR]: "Custom internal error message",
  },
});

// TypeScript autocomplete and validation for error messages
const message = authAdvanced.getErrorMessage(ErrorMessageKeys.INVALID_TOKEN); // ✅ Type safe
const messageWithParams = authAdvanced.getErrorMessageWithParams(
  ErrorMessageKeys.DEVICE_LIMIT_EXCEEDED,
  { maxDevices: 3, currentDevices: 4 }
); // ✅ Type safe with parameters
```

## Production Features

### Rate Limiting

Protect your authentication endpoints from abuse with built-in rate limiting:

```javascript
const auth = createAuth({
  secret: process.env.JWT_SECRET,
  enableRateLimiting: true,
  rateLimitStorage: "redis", // or 'memory'
  redisClient: redisClient,
});

// Use rate limiters on specific endpoints
app.post("/login", auth.rateLimiter.login.createMiddleware(), (req, res) => {
  // Login logic - limited to 5 attempts per 15 minutes
});

app.post(
  "/password-reset",
  auth.rateLimiter.passwordReset.createMiddleware(),
  (req, res) => {
    // Password reset - limited to 3 attempts per hour
  }
);

app.post(
  "/refresh",
  auth.rateLimiter.tokenRefresh.createMiddleware(),
  (req, res) => {
    // Token refresh - limited to 10 attempts per minute
  }
);
```

**Predefined Rate Limiters:**

- **Login**: 5 attempts per 15 minutes
- **Password Reset**: 3 attempts per hour
- **Token Refresh**: 10 attempts per minute
- **API**: 100 requests per 15 minutes

### Rate Limiter Usage Examples

```javascript
// Login endpoint - prevent brute force attacks
app.post(
  "/login",
  auth.rateLimiter.login.createMiddleware(), // 5 attempts per 15 minutes
  (req, res) => {
    // Login logic
  }
);

// Password reset - prevent spam
app.post(
  "/password-reset",
  auth.rateLimiter.passwordReset.createMiddleware(), // 3 attempts per hour
  (req, res) => {
    // Password reset logic
  }
);

// Token refresh - prevent abuse
app.post(
  "/refresh",
  auth.rateLimiter.tokenRefresh.createMiddleware(), // 10 attempts per minute
  (req, res) => {
    // Token refresh logic
  }
);

// General API endpoints - prevent overuse
app.get(
  "/api/data",
  auth.rateLimiter.api.createMiddleware(), // 100 requests per 15 minutes
  auth.protect(),
  (req, res) => {
    // API logic
  }
);
```

### Custom Rate Limiters

You can also create custom rate limiters for specific needs:

```javascript
const { RateLimiter, MemoryRateLimitStorage } = require("jwt-auth-suite");

// Custom rate limiter for file uploads
const fileUploadLimiter = new RateLimiter(
  {
    windowMs: 60 * 60 * 1000, // 1 hour
    maxAttempts: 10, // 10 uploads per hour
    keyGenerator: (req) => `file_upload:${req.ip}`,
    message: "Too many file uploads, please try again later",
  },
  new MemoryRateLimitStorage()
);

// Use custom rate limiter
app.post(
  "/upload",
  fileUploadLimiter.createMiddleware(),
  auth.protect(),
  (req, res) => {
    // File upload logic
  }
);
```

### Security Logging

Comprehensive security event logging for monitoring and compliance:

```javascript
const auth = createAuth({
  secret: process.env.JWT_SECRET,
  enableSecurityLogging: true,
  securityLoggerConfig: {
    enableConsoleLogging: true,
    enableFileLogging: true,
    logFilePath: "./security.log",
    enableRemoteLogging: true,
    remoteEndpoint: "https://your-monitoring-service.com/logs",
    logLevel: "MEDIUM",
  },
});

// Automatic security logging
app.post("/login", (req, res) => {
  // Success logging
  auth.securityLogger.logAuthSuccess(userId, req, { method: "password" });

  // Failure logging
  auth.securityLogger.logAuthFailure(req, "Invalid password");

  // Suspicious activity logging
  auth.securityLogger.logSuspiciousActivity(req, "Multiple failed attempts");
});
```

**Security Event Types:**

- `LOGIN_SUCCESS` - Successful authentication
- `LOGIN_FAILURE` - Failed authentication attempts
- `TOKEN_GENERATED` - New tokens created
- `TOKEN_BLACKLISTED` - Tokens invalidated
- `RATE_LIMIT_EXCEEDED` - Rate limits exceeded
- `SUSPICIOUS_ACTIVITY` - Unusual behavior detected
- `PERMISSION_DENIED` - Access denied due to insufficient permissions

### Metrics Collection

Real-time performance monitoring and analytics:

```javascript
const auth = createAuth({
  secret: process.env.JWT_SECRET,
  enableMetrics: true,
  metricsConfig: {
    enableConsoleMetrics: true,
    enableFileMetrics: true,
    metricsFilePath: "./metrics.log",
    enableRemoteMetrics: true,
    remoteEndpoint: "https://your-monitoring-service.com/metrics",
    collectionInterval: 60000, // 1 minute
  },
});

// Automatic metrics collection
app.use(auth.metrics.createRequestMetricsMiddleware());

// Manual metrics recording
auth.metrics.recordAuthSuccess(userId, "password");
auth.metrics.recordTokenGenerated("access", userId);
auth.metrics.increment("custom_counter");
auth.metrics.gauge("active_users", 42);

// Get metrics summary
const summary = auth.metrics.getSummary();
console.log("Performance metrics:", summary);
```

**Metric Types:**

- **Counters**: Total requests, successful logins, failed attempts
- **Gauges**: Active users, memory usage, current load
- **Timers**: Request duration, login time, token generation time
- **Histograms**: Response size, error rates, performance distribution

### Remote Logging & Monitoring

Send logs and metrics to external monitoring services:

```javascript
// Security Logging to Remote Service
const auth = createAuth({
  secret: process.env.JWT_SECRET,
  enableSecurityLogging: true,
  securityLoggerConfig: {
    enableRemoteLogging: true,
    remoteEndpoint: "https://your-security-service.com/api/logs",
    logLevel: "HIGH", // Only log HIGH and CRITICAL events
  },
});

// Metrics to Monitoring Service
const auth = createAuth({
  secret: process.env.JWT_SECRET,
  enableMetrics: true,
  metricsConfig: {
    enableRemoteMetrics: true,
    remoteEndpoint: "https://your-monitoring-service.com/api/metrics",
    collectionInterval: 30000, // Send every 30 seconds
  },
});
```

**Remote Service Integration:**

- **Security Logs**: Send to SIEM systems, security monitoring platforms
- **Metrics**: Send to Prometheus, Grafana, DataDog, New Relic
- **Alerts**: Configure alerts based on security events and metrics
- **Dashboards**: Create real-time monitoring dashboards

### Production Configuration Example

Complete production setup with all features:

```javascript
const auth = createAuth({
  // Basic JWT settings
  secret: process.env.JWT_SECRET,
  accessExpiry: "15m",
  refreshExpiry: "7d",

  // Production features
  enableRateLimiting: true,
  enableSecurityLogging: true,
  enableMetrics: true,
  enableTenants: true,
  enableRefreshRotation: true,

  // Rate limiting
  rateLimitStorage: "redis",
  redisClient: redisClient,

  // Security logging
  securityLoggerConfig: {
    enableConsoleLogging: true,
    enableFileLogging: true,
    logFilePath: "./logs/security.log",
    enableRemoteLogging: true,
    remoteEndpoint: process.env.SECURITY_LOG_ENDPOINT,
    logLevel: "MEDIUM",
  },

  // Metrics collection
  metricsConfig: {
    enableConsoleMetrics: false,
    enableFileMetrics: true,
    metricsFilePath: "./logs/metrics.log",
    enableRemoteMetrics: true,
    remoteEndpoint: process.env.METRICS_ENDPOINT,
    collectionInterval: 60000,
  },

  // Database integration
  prismaClient: prisma, // or mongoClient, sequelizeClient
});
```

## Framework Integrations

### Express.js (Most Common)

```javascript
const express = require("express");
const { createAuth } = require("jwt-auth-suite");

const app = express();
app.use(express.json());

const auth = createAuth({
  secret: process.env.JWT_SECRET,
  roles: ["admin", "user"],
  enableRateLimiting: true,
});

// Global middleware
app.use(auth.securityLogger.createMiddleware());
app.use(auth.metrics.createRequestMetricsMiddleware());

// Routes
app.post("/login", auth.rateLimiter.login.createMiddleware(), (req, res) => {
  // Login logic
});

app.get(
  "/profile",
  auth.rateLimiter.api.createMiddleware(),
  auth.protect(),
  (req, res) => {
    res.json({ user: req.user });
  }
);

app.listen(3000);
```

### Next.js API Routes

```javascript
// pages/api/profile.js
import { createAuth } from "jwt-auth-suite";

const auth = createAuth({
  secret: process.env.JWT_SECRET,
  roles: ["admin", "user"],
});

export default function handler(req, res) {
  // Apply middleware manually
  auth.protect()(req, res, (err) => {
    if (err) return res.status(401).json({ error: "Unauthorized" });

    res.json({ user: req.user });
  });
}
```

### Fastify (Coming Soon)

```javascript
// Note: Fastify adapter coming in future release
const fastify = require("fastify");
const { createAuth } = require("jwt-auth-suite");

const app = fastify();
const auth = createAuth({
  secret: process.env.JWT_SECRET,
  roles: ["admin", "user"],
});

// Register as plugin
app.register(auth.fastifyPlugin);
```

### NestJS (Coming Soon)

```typescript
// Note: NestJS adapter coming in future release
import { Module } from "@nestjs/common";
import { JWTAuthSuiteModule } from "jwt-auth-suite/nestjs";

@Module({
  imports: [
    JWTAuthSuiteModule.forRoot({
      secret: process.env.JWT_SECRET,
      roles: ["admin", "user"],
      enableRateLimiting: true,
    }),
  ],
})
export class AppModule {}
```

## Advanced Features

### JWT Blacklisting

Secure logout by blacklisting tokens:

```javascript
const auth = createAuth({
  secret: process.env.JWT_SECRET,
  blacklistStorage: "redis", // or 'memory', 'database'
  redisClient: redisClient,
});

// Logout - blacklist token
app.post("/logout", auth.protect(), async (req, res) => {
  const token = auth.extractToken(req);
  await auth.blacklistToken(token);
  res.json({ message: "Logged out successfully" });
});

// Logout from all devices
app.post("/logout-all", auth.protect(), async (req, res) => {
  await auth.blacklistUser(req.user.id);
  res.json({ message: "Logged out from all devices" });
});
```

### Password Hashing

Built-in password security:

```javascript
const auth = createAuth({
  secret: process.env.JWT_SECRET,
  passwordSaltRounds: 12,
});

// Hash password during registration
app.post("/register", async (req, res) => {
  const { email, password } = req.body;

  // Validate password strength
  const validation = auth.validatePassword(password);
  if (!validation.valid) {
    return res.status(400).json({ errors: validation.errors });
  }

  // Hash password
  const hashedPassword = await auth.hashPassword(password);

  // Store user with hashed password
  const user = await createUser({ email, password: hashedPassword });
  res.json({ message: "User created" });
});

// Verify password during login
app.post("/login", async (req, res) => {
  const { email, password } = req.body;
  const user = await getUserByEmail(email);

  if (await auth.verifyPassword(password, user.password)) {
    const token = auth.generateToken({ sub: user.id, email: user.email });
    res.json({ token });
  } else {
    res.status(401).json({ error: "Invalid credentials" });
  }
});
```

### Multi-Tenant Support

SaaS-ready tenant isolation:

```javascript
const auth = createAuth({
  secret: process.env.JWT_SECRET,
  enableTenants: true,
});

// Register tenants
auth.registerTenant("acme-corp", {
  name: "Acme Corporation",
  subdomain: "acme",
  domain: "acme.myapp.com",
});

auth.registerTenant("beta-inc", {
  name: "Beta Inc",
  subdomain: "beta",
  domain: "beta.myapp.com",
});

// Tenant resolution middleware
app.use(auth.tenantMiddleware.resolveTenant());

// Tenant-specific routes
app.get("/dashboard", auth.protect(), (req, res) => {
  res.json({
    message: `Welcome to ${req.tenant.name}`,
    tenant: req.tenant,
    user: req.user,
  });
});

// Tenant admin routes
app.get("/admin", auth.tenantMiddleware.requireTenantAdmin(), (req, res) => {
  res.json({ message: "Tenant admin panel" });
});
```

### Multi-Device Login Support

**Yes! JWT Auth Suite fully supports multi-device login.** The same user can have multiple active sessions across different devices with different access tokens and refresh tokens.

#### **🌍 Internationalization (i18n) Support**

JWT Auth Suite includes built-in i18n support for multi-login messages and error handling:

```javascript
const { createAuth, ErrorMessageKeys } = require("superjwt");

const auth = createAuth({
  secret: process.env.JWT_SECRET,
  multiLogin: false,
  enableRefreshRotation: true,

  // i18n configuration
  i18n: {
    locale: "es", // Default locale
    fallbackLocale: "en", // Fallback when translation not found
    messages: {
      // Custom messages for specific locales using enums
      es: {
        [ErrorMessageKeys.PREVIOUS_SESSIONS_LOGGED_OUT]:
          "Sesiones anteriores cerradas por nuevo inicio de sesión",
        [ErrorMessageKeys.SINGLE_DEVICE_ONLY]: "Solo un dispositivo permitido",
        [ErrorMessageKeys.INVALID_TOKEN]: "Token inválido",
        [ErrorMessageKeys.TOKEN_EXPIRED]: "Token expirado",
        [ErrorMessageKeys.UNAUTHORIZED]: "Acceso no autorizado",
        [ErrorMessageKeys.FORBIDDEN]: "Acceso prohibido",
        [ErrorMessageKeys.NOT_FOUND]: "Recurso no encontrado",
        [ErrorMessageKeys.INTERNAL_ERROR]: "Error interno del servidor",
      },
    },
  },

  // Custom error messages (overrides i18n) using enums
  errorMessages: {
    [ErrorMessageKeys.PREVIOUS_SESSIONS_LOGGED_OUT]:
      "Your previous sessions have been logged out",
    [ErrorMessageKeys.SINGLE_DEVICE_ONLY]:
      "Only one device allowed for security reasons",
    [ErrorMessageKeys.INVALID_TOKEN]: "Custom invalid token message",
    [ErrorMessageKeys.UNAUTHORIZED]: "Custom unauthorized message",
  },
});
```

#### **📝 Supported Languages**

Built-in support for:

- 🇺🇸 **English** (en) - Default
- 🇪🇸 **Spanish** (es)
- 🇫🇷 **French** (fr)
- 🇩🇪 **German** (de)
- 🇵🇹 **Portuguese** (pt)

#### **🔑 ErrorMessageKeys Enum**

For type safety and consistency, use the `ErrorMessageKeys` enum instead of string literals:

```javascript
const { ErrorMessageKeys } = require("superjwt");

// Available error message keys
console.log(ErrorMessageKeys.INVALID_TOKEN); // 'INVALID_TOKEN'
console.log(ErrorMessageKeys.TOKEN_EXPIRED); // 'TOKEN_EXPIRED'
console.log(ErrorMessageKeys.UNAUTHORIZED); // 'UNAUTHORIZED'
console.log(ErrorMessageKeys.FORBIDDEN); // 'FORBIDDEN'
console.log(ErrorMessageKeys.NOT_FOUND); // 'NOT_FOUND'
console.log(ErrorMessageKeys.INTERNAL_ERROR); // 'INTERNAL_ERROR'

// Multi-login specific keys
console.log(ErrorMessageKeys.PREVIOUS_SESSIONS_LOGGED_OUT); // 'PREVIOUS_SESSIONS_LOGGED_OUT'
console.log(ErrorMessageKeys.SINGLE_DEVICE_ONLY); // 'SINGLE_DEVICE_ONLY'
console.log(ErrorMessageKeys.DEVICE_LIMIT_EXCEEDED); // 'DEVICE_LIMIT_EXCEEDED'
console.log(ErrorMessageKeys.MULTI_LOGIN_DISABLED); // 'MULTI_LOGIN_DISABLED'

// General auth keys
console.log(ErrorMessageKeys.INVALID_CREDENTIALS); // 'INVALID_CREDENTIALS'
console.log(ErrorMessageKeys.ACCESS_DENIED); // 'ACCESS_DENIED'
console.log(ErrorMessageKeys.RATE_LIMIT_EXCEEDED); // 'RATE_LIMIT_EXCEEDED'
```

**Benefits of using enums:**

- ✅ **Type Safety**: TypeScript autocomplete and validation
- ✅ **Consistency**: Same keys used everywhere
- ✅ **Refactoring**: Easy to rename keys across codebase
- ✅ **Documentation**: Self-documenting code
- ✅ **Error Prevention**: No typos in error message keys

#### **🔧 Dynamic Locale Switching**

```javascript
const { ErrorMessageKeys } = require("superjwt");

// Set locale dynamically
auth.setLocale("es");

// Get current locale
const currentLocale = auth.getLocale(); // 'es'

// Get localized error message using enum
const message = auth.getErrorMessage(
  ErrorMessageKeys.PREVIOUS_SESSIONS_LOGGED_OUT,
  "es"
);
// Returns: "Sesiones anteriores cerradas por nuevo inicio de sesión"

// Get message with parameters using enum
const messageWithParams = auth.getErrorMessageWithParams(
  ErrorMessageKeys.DEVICE_LIMIT_EXCEEDED,
  {
    maxDevices: 3,
    currentDevices: 4,
  },
  "en"
);
// Returns: "Maximum 3 devices allowed. You currently have 4 devices logged in"
```

#### **🎯 Custom Error Messages**

```javascript
const { ErrorMessageKeys } = require("superjwt");

// Add custom messages for a locale using enums
auth.addMessages("ja", {
  [ErrorMessageKeys.PREVIOUS_SESSIONS_LOGGED_OUT]:
    "前のセッションは新しいログインによりログアウトされました",
  [ErrorMessageKeys.SINGLE_DEVICE_ONLY]:
    "セキュリティ上の理由により、1つのデバイスのみ許可されています",
  [ErrorMessageKeys.INVALID_TOKEN]: "無効なトークンです",
  [ErrorMessageKeys.TOKEN_EXPIRED]: "トークンの有効期限が切れました",
  [ErrorMessageKeys.UNAUTHORIZED]: "認証が必要です",
  [ErrorMessageKeys.FORBIDDEN]: "アクセスが禁止されています",
  [ErrorMessageKeys.NOT_FOUND]: "リソースが見つかりません",
  [ErrorMessageKeys.INTERNAL_ERROR]: "内部サーバーエラー",
});

// Use custom messages with enum
auth.setLocale("ja");
const message = auth.getErrorMessage(
  ErrorMessageKeys.PREVIOUS_SESSIONS_LOGGED_OUT
);
// Returns: "前のセッションは新しいログインによりログアウトされました"
```

#### **Configurable Multi-Device Login**

You can control whether users can have multiple active sessions using the `multiLogin` configuration option:

```javascript
// Allow multiple device logins (default)
const auth = createAuth({
  secret: process.env.JWT_SECRET,
  multiLogin: true, // Users can be logged in on multiple devices
  enableRefreshRotation: true,
});

// Single device login only
const auth = createAuth({
  secret: process.env.JWT_SECRET,
  multiLogin: false, // Only one device can be logged in at a time
  enableRefreshRotation: true,
});
```

#### **Single-Device Login Behavior**

When `multiLogin: false`:

- ✅ **New login automatically logs out all other devices**
- ✅ **Only the latest device remains active**
- ✅ **Previous tokens are immediately invalidated**
- ✅ **Perfect for security-sensitive applications**

```javascript
// Example: Banking app with single-device login
const auth = createAuth({
  secret: process.env.JWT_SECRET,
  multiLogin: false, // Only one device at a time
  enableRefreshRotation: true,
});

// When user logs in from new device:
// 1. All existing tokens are revoked
// 2. Only new device gets valid tokens
// 3. Other devices get "Token expired" errors
```

#### **How Multi-Device Login Works:**

```javascript
const auth = createAuth({
  secret: process.env.JWT_SECRET,
  enableRefreshRotation: true,
  blacklistStorage: "redis",
});

// Login from Device 1 (Mobile)
app.post("/login", async (req, res) => {
  const { email, password } = req.body;
  const user = await authenticateUser(email, password);

  // Generate tokens with device ID
  const result = await auth.generateRefreshTokenWithRotation(user, {
    deviceId: req.headers["device-id"] || "mobile-123", // Device identifier
    maxFamilySize: 5, // Max 5 tokens per device
  });

  res.json({
    accessToken: result.accessToken,
    refreshToken: result.refreshToken,
    deviceId: result.deviceId,
    familyId: result.familyId,
  });
});

// Login from Device 2 (Desktop) - Same user, different device
// This will create a separate token family for the desktop
app.post("/login", async (req, res) => {
  const { email, password } = req.body;
  const user = await authenticateUser(email, password);

  const result = await auth.generateRefreshTokenWithRotation(user, {
    deviceId: req.headers["device-id"] || "desktop-456", // Different device
    maxFamilySize: 5,
  });

  res.json({
    accessToken: result.accessToken,
    refreshToken: result.refreshToken,
    deviceId: result.deviceId,
    familyId: result.familyId,
  });
});
```

#### **Device Management:**

```javascript
// Get all active sessions for a user
app.get("/sessions", auth.protect(), async (req, res) => {
  const activeTokens = await auth.refreshManager.getUserActiveTokens(
    req.user.id
  );

  res.json({
    sessions: activeTokens.map((token) => ({
      deviceId: token.deviceId,
      createdAt: token.createdAt,
      isActive: token.isActive,
    })),
  });
});

// Logout from specific device
app.post("/logout-device", auth.protect(), async (req, res) => {
  const { deviceId } = req.body;

  await auth.refreshManager.revokeDeviceTokens(req.user.id, deviceId);

  res.json({ message: `Logged out from device: ${deviceId}` });
});

// Logout from all devices
app.post("/logout-all", auth.protect(), async (req, res) => {
  await auth.refreshManager.revokeUserTokens(req.user.id);

  res.json({ message: "Logged out from all devices" });
});
```

#### **Multi-Device Features:**

| Feature                | Description                                       |
| ---------------------- | ------------------------------------------------- |
| **Multiple Sessions**  | Same user can be logged in on multiple devices    |
| **Device Tracking**    | Each device gets a unique `deviceId`              |
| **Independent Tokens** | Each device has its own access/refresh token pair |
| **Device Management**  | Logout from specific devices or all devices       |
| **Token Families**     | Tokens organized by device for better management  |
| **Security**           | Compromised device doesn't affect other devices   |

#### **🌐 Real-World i18n Example**

```javascript
// Express app with i18n support
const express = require("express");
const { createAuth, ErrorMessageKeys } = require("superjwt");

const app = express();
app.use(express.json());

// Initialize auth with i18n
const auth = createAuth({
  secret: process.env.JWT_SECRET,
  multiLogin: false, // Single device only
  enableRefreshRotation: true,
  i18n: {
    locale: "en",
    fallbackLocale: "en",
  },
});

// Middleware to detect user locale
app.use((req, res, next) => {
  const locale =
    req.headers["accept-language"]?.split(",")[0]?.split("-")[0] || "en";
  auth.setLocale(locale);
  next();
});

// Login endpoint with localized messages
app.post("/login", async (req, res) => {
  const { email, password } = req.body;
  const user = await authenticateUser(email, password);

  const result = await auth.generateRefreshTokenWithRotation(user, {
    deviceId: req.headers["device-id"],
  });

  res.json({
    accessToken: result.accessToken,
    refreshToken: result.refreshToken,
    deviceId: result.deviceId,
    message: result.message, // Localized message
    locale: auth.getLocale(),
  });
});

// Error handling with localized messages using enums
app.use((err, req, res, next) => {
  if (err.name === "TokenExpiredError") {
    return res.status(401).json({
      error: auth.getErrorMessage(ErrorMessageKeys.TOKEN_EXPIRED),
      locale: auth.getLocale(),
    });
  }

  if (err.name === "JsonWebTokenError") {
    return res.status(401).json({
      error: auth.getErrorMessage(ErrorMessageKeys.INVALID_TOKEN),
      locale: auth.getLocale(),
    });
  }

  if (err.name === "UnauthorizedError") {
    return res.status(401).json({
      error: auth.getErrorMessage(ErrorMessageKeys.UNAUTHORIZED),
      locale: auth.getLocale(),
    });
  }

  if (err.name === "ForbiddenError") {
    return res.status(403).json({
      error: auth.getErrorMessage(ErrorMessageKeys.FORBIDDEN),
      locale: auth.getLocale(),
    });
  }

  next(err);
});
```

#### **Real-World Examples:**

##### **Multi-Device Login (multiLogin: true)**

```javascript
// User logs in from iPhone
const mobileLogin = await fetch("/login", {
  method: "POST",
  headers: {
    "Content-Type": "application/json",
    "device-id": "iphone-12-pro-abc123",
  },
  body: JSON.stringify({ email: "user@example.com", password: "password123" }),
});

// Response: { accessToken: 'eyJ...', refreshToken: 'eyJ...', deviceId: 'iphone-12-pro-abc123' }

// Same user logs in from MacBook
const desktopLogin = await fetch("/login", {
  method: "POST",
  headers: {
    "Content-Type": "application/json",
    "device-id": "macbook-pro-xyz789",
  },
  body: JSON.stringify({ email: "user@example.com", password: "password123" }),
});

// Response: { accessToken: 'eyJ...', refreshToken: 'eyJ...', deviceId: 'macbook-pro-xyz789' }

// Both devices are now logged in independently!
// Each has its own tokens and can refresh them separately
```

##### **Single-Device Login (multiLogin: false)**

```javascript
// User logs in from iPhone
const mobileLogin = await fetch("/login", {
  method: "POST",
  headers: {
    "Content-Type": "application/json",
    "device-id": "iphone-12-pro-abc123",
  },
  body: JSON.stringify({ email: "user@example.com", password: "password123" }),
});

// Response: { accessToken: 'eyJ...', refreshToken: 'eyJ...', deviceId: 'iphone-12-pro-abc123' }

// Same user tries to log in from MacBook
const desktopLogin = await fetch("/login", {
  method: "POST",
  headers: {
    "Content-Type": "application/json",
    "device-id": "macbook-pro-xyz789",
  },
  body: JSON.stringify({ email: "user@example.com", password: "password123" }),
});

// Response: { accessToken: 'eyJ...', refreshToken: 'eyJ...', deviceId: 'macbook-pro-xyz789' }

// iPhone tokens are now invalidated!
// Only MacBook has valid tokens
// iPhone will get "Token expired" errors on next request
```

#### **Checking Multi-Login Status:**

```javascript
// Check if multi-login is enabled
app.get("/auth-config", (req, res) => {
  res.json({
    multiLoginEnabled: auth.isMultiLoginEnabled(),
    // Other auth configuration...
  });
});

// Conditional behavior based on multi-login setting
app.post("/login", async (req, res) => {
  const { email, password } = req.body;
  const user = await authenticateUser(email, password);

  if (auth.isMultiLoginEnabled()) {
    // Allow multiple devices
    const result = await auth.generateRefreshTokenWithRotation(user, {
      deviceId: req.headers["device-id"],
    });
    res.json({
      accessToken: result.accessToken,
      refreshToken: result.refreshToken,
      deviceId: result.deviceId,
      multiLogin: true,
    });
  } else {
    // Single device only - previous devices will be logged out
    const result = await auth.generateRefreshTokenWithRotation(user, {
      deviceId: req.headers["device-id"],
    });
    res.json({
      accessToken: result.accessToken,
      refreshToken: result.refreshToken,
      deviceId: result.deviceId,
      multiLogin: false,
      message: "Previous sessions have been logged out",
    });
  }
});
```

#### **Use Cases:**

| Application Type     | Multi-Login Setting | Reason                                           |
| -------------------- | ------------------- | ------------------------------------------------ |
| **Social Media**     | `true`              | Users expect to be logged in on multiple devices |
| **E-commerce**       | `true`              | Users shop on phone, tablet, and desktop         |
| **Banking/Finance**  | `false`             | Security requirement - only one active session   |
| **Healthcare**       | `false`             | HIPAA compliance - single device access          |
| **Enterprise Admin** | `false`             | Security - prevent unauthorized access           |
| **Gaming**           | `true`              | Users play on different devices                  |
| **Streaming**        | `true`              | Users watch on TV, phone, tablet                 |

#### **Device Detection Strategies:**

```javascript
// Strategy 1: Client sends device ID
app.post("/login", async (req, res) => {
  const deviceId = req.headers["device-id"] || req.headers["x-device-id"];
  // Use provided device ID or generate one
});

// Strategy 2: Generate device ID from user agent + IP
app.post("/login", async (req, res) => {
  const userAgent = req.headers["user-agent"];
  const ip = req.ip;
  const deviceId = crypto
    .createHash("md5")
    .update(`${userAgent}-${ip}`)
    .digest("hex");
  // Use generated device ID
});

// Strategy 3: Use device fingerprinting
app.post("/login", async (req, res) => {
  const fingerprint = req.body.fingerprint; // From client-side fingerprinting
  const deviceId = fingerprint || generateDeviceId();
  // Use fingerprint as device ID
});
```

### Refresh Token Rotation

Enhanced security with automatic token rotation:

```javascript
const auth = createAuth({
  secret: process.env.JWT_SECRET,
  enableRefreshRotation: true,
  blacklistStorage: "redis",
});

// Login with refresh token rotation
app.post("/login", async (req, res) => {
  const { email, password } = req.body;
  const user = await authenticateUser(email, password);

  const result = await auth.generateRefreshTokenWithRotation(user, {
    deviceId: req.headers["device-id"],
    maxFamilySize: 5,
  });

  res.json({
    accessToken: result.accessToken,
    refreshToken: result.refreshToken,
    familyId: result.familyId,
  });
});

// Refresh tokens with rotation
app.post("/refresh", async (req, res) => {
  const { refreshToken } = req.body;
  const user = await getUserFromToken(refreshToken);

  const result = await auth.rotateRefreshToken(refreshToken, user);

  res.json({
    accessToken: result.accessToken,
    refreshToken: result.refreshToken,
  });
});

// Revoke all user tokens
app.post("/revoke-all", auth.protect(), async (req, res) => {
  await auth.revokeUserTokens(req.user.id);
  res.json({ message: "All tokens revoked" });
});
```

## Complete Example: Registration to Protected Routes

Here's a complete example showing the full flow from user registration to accessing protected routes:

```javascript
const express = require("express");
const { initAuth } = require("jwt-auth-suite");

const app = express();
app.use(express.json());

// Initialize JWT Auth Suite
const auth = initAuth({
  secret: process.env.JWT_SECRET,
  accessExpiry: "15m",
  roles: ["admin", "moderator", "user"],
  permissions: ["read", "write", "delete", "manage_users"],
});

// Mock database
const users = {};

// Helper function to assign permissions based on role
function getPermissionsForRole(role) {
  const rolePermissions = {
    admin: ["read", "write", "delete", "manage_users"],
    moderator: ["read", "write", "delete"],
    user: ["read", "write"],
  };
  return rolePermissions[role] || ["read"];
}

// 1. User Registration
app.post("/register", (req, res) => {
  const { email, password, role = "user" } = req.body;

  // Validate role
  const allowedRoles = ["admin", "moderator", "user"];
  if (!allowedRoles.includes(role)) {
    return res.status(400).json({ error: "Invalid role" });
  }

  // Get permissions based on role
  const permissions = getPermissionsForRole(role);

  // Store user
  users[email] = {
    id: Date.now().toString(),
    password, // In real app, hash this
    role,
    permissions,
  };

  res.json({
    message: "User registered",
    user: { email, role, permissions },
  });
});

// 2. User Login
app.post("/login", (req, res) => {
  const { email, password } = req.body;

  const user = users[email];
  if (!user || user.password !== password) {
    return res.status(401).json({ error: "Invalid credentials" });
  }

  // Generate token with user data
  const token = auth.generateToken({
    sub: user.id,
    email: user.email,
    role: user.role,
    permissions: user.permissions,
  });

  res.json({
    message: "Login successful",
    token,
    user: { email: user.email, role: user.role, permissions: user.permissions },
  });
});

// 3. Protected Routes
app.get("/profile", auth.protect(), (req, res) => {
  res.json({ message: "Profile data", user: req.user });
});

app.get("/admin-panel", auth.requireRole("admin"), (req, res) => {
  res.json({ message: "Admin panel", user: req.user });
});

app.get("/posts", auth.requirePermission("read"), (req, res) => {
  res.json({ message: "Posts list", user: req.user });
});

app.post("/posts", auth.requirePermission("write"), (req, res) => {
  res.json({ message: "Post created", user: req.user });
});

app.delete("/posts/:id", auth.requirePermission("delete"), (req, res) => {
  res.json({ message: "Post deleted", user: req.user });
});

app.listen(3000);
```

### Test the Flow

```bash
# 1. Register an admin user
curl -X POST http://localhost:3000/register \
  -H "Content-Type: application/json" \
  -d '{"email":"admin@test.com","password":"admin123","role":"admin"}'

# 2. Login to get token
curl -X POST http://localhost:3000/login \
  -H "Content-Type: application/json" \
  -d '{"email":"admin@test.com","password":"admin123"}'

# 3. Use token to access protected routes
curl -X GET http://localhost:3000/admin-panel \
  -H "Authorization: Bearer YOUR_TOKEN"
```

## Examples

### Cookie-based Authentication

```javascript
const auth = initAuth({
  secret: process.env.JWT_SECRET,
  storage: "cookie",
  cookieName: "auth_token",
  cookieOptions: {
    httpOnly: true,
    secure: true, // Use with HTTPS
    sameSite: "strict",
  },
});
```

## Time Format

Time strings support the following formats:

- `15s` - 15 seconds
- `5m` - 5 minutes
- `2h` - 2 hours
- `7d` - 7 days

## Security Best Practices

### 🔒 Production Security Checklist

#### ✅ **Secret Management**

```javascript
// ❌ NEVER do this
const auth = initAuth({
  secret: "my-secret", // Hardcoded secret
  roles: ["user"],
});

// ✅ ALWAYS do this
const auth = initAuth({
  secret: process.env.JWT_SECRET, // Environment variable
  roles: ["user"],
});

// ✅ Use strong secrets (32+ characters)
// Generate with: node -e "console.log(require('crypto').randomBytes(32).toString('hex'))"
```

#### ✅ **Token Security**

```javascript
// ✅ Short-lived access tokens
const auth = initAuth({
  secret: process.env.JWT_SECRET,
  accessExpiry: "15m", // 15 minutes
  refreshExpiry: "7d", // 7 days
  roles: ["user"],
});

// ✅ Use HTTPS in production
// ✅ Implement token rotation
// ✅ Blacklist tokens on logout
```

#### ✅ **Rate Limiting**

```javascript
// ✅ Always enable rate limiting in production
const auth = createAuth({
  secret: process.env.JWT_SECRET,
  enableRateLimiting: true,
  rateLimitStorage: "redis", // Use Redis for production
  roles: ["user"],
});

// ✅ Apply rate limiting to all auth endpoints
app.post("/login", auth.rateLimiter.login.createMiddleware(), handler);
app.post("/register", auth.rateLimiter.login.createMiddleware(), handler);
app.post(
  "/password-reset",
  auth.rateLimiter.passwordReset.createMiddleware(),
  handler
);
```

#### ✅ **Security Logging**

```javascript
// ✅ Enable comprehensive security logging
const auth = createAuth({
  secret: process.env.JWT_SECRET,
  enableSecurityLogging: true,
  securityLoggerConfig: {
    enableConsoleLogging: true,
    enableFileLogging: true,
    logLevel: "HIGH", // Log all security events
    remoteEndpoint: "https://your-security-monitoring.com/logs",
  },
  roles: ["user"],
});
```

#### ✅ **Input Validation**

```javascript
// ✅ Always validate input
app.post("/login", auth.rateLimiter.login.createMiddleware(), (req, res) => {
  const { email, password } = req.body;

  // Validate input
  if (!email || !password) {
    return res.status(400).json({ error: "Email and password required" });
  }

  if (!isValidEmail(email)) {
    return res.status(400).json({ error: "Invalid email format" });
  }

  // Continue with authentication
});
```

#### ✅ **Error Handling**

```javascript
// ✅ Don't expose sensitive information
app.use((err, req, res, next) => {
  if (err.name === "JsonWebTokenError") {
    return res.status(401).json({ error: "Invalid token" });
  }

  if (err.name === "TokenExpiredError") {
    return res.status(401).json({ error: "Token expired" });
  }

  // Log the actual error for debugging
  console.error(err);

  // Return generic error to client
  res.status(500).json({ error: "Internal server error" });
});
```

### 🚨 **Security Anti-Patterns**

#### ❌ **Never Do These**

```javascript
// ❌ Don't store secrets in code
const secret = "my-secret";

// ❌ Don't use weak secrets
const secret = "123";

// ❌ Don't disable rate limiting in production
const auth = createAuth({
  enableRateLimiting: false, // DANGEROUS!
});

// ❌ Don't log sensitive data
console.log("User password:", password);

// ❌ Don't expose internal errors
res.status(500).json({ error: err.message }); // Exposes stack traces
```

### 🔐 **Advanced Security Features**

#### **Token Rotation**

```javascript
// ✅ Implement refresh token rotation
const auth = createAuth({
  secret: process.env.JWT_SECRET,
  enableRefreshRotation: true,
  roles: ["user"],
});

// ✅ Rotate tokens on refresh
app.post("/refresh", async (req, res) => {
  const { refreshToken } = req.body;

  try {
    const newTokens = await auth.rotateRefreshToken(refreshToken);
    res.json(newTokens);
  } catch (error) {
    res.status(401).json({ error: "Invalid refresh token" });
  }
});
```

#### **Multi-Factor Authentication**

```javascript
// ✅ Implement MFA with TOTP
const speakeasy = require("speakeasy");

app.post(
  "/login",
  auth.rateLimiter.login.createMiddleware(),
  async (req, res) => {
    const { email, password, totp } = req.body;

    // Verify password
    const user = await verifyPassword(email, password);
    if (!user) {
      return res.status(401).json({ error: "Invalid credentials" });
    }

    // Verify TOTP
    const verified = speakeasy.totp.verify({
      secret: user.mfaSecret,
      encoding: "base32",
      token: totp,
      window: 2,
    });

    if (!verified) {
      return res.status(401).json({ error: "Invalid MFA code" });
    }

    // Generate token
    const token = auth.generateToken({
      sub: user.id,
      email: user.email,
      role: user.role,
      mfaVerified: true,
    });

    res.json({ token });
  }
);
```

#### **Audit Logging**

```javascript
// ✅ Log all sensitive operations
app.post(
  "/change-password",
  auth.rateLimiter.passwordReset.createMiddleware(),
  auth.protect(),
  async (req, res) => {
    const { oldPassword, newPassword } = req.body;

    // Log password change attempt
    auth.securityLogger.logPasswordChangeAttempt(req.user.id, req);

    try {
      await changePassword(req.user.id, oldPassword, newPassword);

      // Log successful change
      auth.securityLogger.logPasswordChanged(req.user.id, req);

      res.json({ message: "Password changed successfully" });
    } catch (error) {
      // Log failed attempt
      auth.securityLogger.logPasswordChangeFailed(
        req.user.id,
        req,
        error.message
      );

      res.status(400).json({ error: "Invalid old password" });
    }
  }
);
```

## FAQ

### Q: Where do I assign roles to users?

A: Roles are typically assigned during user registration. You can:

- Set a default role (e.g., 'user') for self-registration
- Let admins assign roles when creating users
- Use invitation-based registration where the role is pre-assigned

### Q: Can users have multiple roles?

A: The current implementation supports one role per user. For multiple roles, you can:

- Use permissions instead of roles for more granular control
- Store multiple roles in the user object and check them manually
- Extend the library to support multiple roles (future feature)

### Q: How do I change a user's role after registration?

A: Update the role in your database and generate a new token:

```javascript
// Update user role in database
await db.users.update(userId, { role: "admin" });

// Generate new token with updated role
const newToken = auth.generateToken({
  sub: userId,
  email: user.email,
  role: "admin", // Updated role
  permissions: getPermissionsForRole("admin"),
});
```

### Q: What's the difference between roles and permissions?

A:

- **Roles** are broad categories (admin, moderator, user)
- **Permissions** are specific actions (read, write, delete, manage_users)
- Users have roles, and roles determine permissions
- You can also assign custom permissions beyond the role

### Q: How do I handle role changes without forcing re-login?

A: Use refresh tokens or implement token refresh:

```javascript
app.post("/refresh-role", auth.protect(), async (req, res) => {
  const user = await db.users.findById(req.user.id);
  const newToken = auth.generateToken({
    sub: user.id,
    email: user.email,
    role: user.role,
    permissions: user.permissions,
  });

  res.json({ token: newToken });
});
```

### Q: Can I use this with databases like MongoDB, PostgreSQL, etc.?

A: Yes! JWT Auth Suite is database-agnostic. Just implement the user lookup functions for your database:

```javascript
// MongoDB example
async function getUserByEmail(email) {
  return await db.collection("users").findOne({ email });
}
```

### Q: Can the same user be logged in on multiple devices?

A: **Yes!** JWT Auth Suite fully supports multi-device login. The same user can have multiple active sessions across different devices, each with their own access and refresh tokens. This is handled through device IDs and token families. See the [Multi-Device Login Support](#multi-device-login-support) section for details.

### Q: How do I manage user sessions across multiple devices?

A: You can:

- **View all sessions**: `auth.refreshManager.getUserActiveTokens(userId)`
- **Logout from specific device**: `auth.refreshManager.revokeDeviceTokens(userId, deviceId)`
- **Logout from all devices**: `auth.refreshManager.revokeUserTokens(userId)`
- **Track device information**: Each token includes `deviceId` and `familyId`

### Q: How do I enable single-device login only?

A: Set `multiLogin: false` in your configuration:

```javascript
const auth = createAuth({
  secret: process.env.JWT_SECRET,
  multiLogin: false, // Only one device at a time
  enableRefreshRotation: true,
});

// When user logs in from new device:
// - All previous tokens are automatically revoked
// - Only the new device remains active
// - Perfect for banking, healthcare, or security-sensitive apps
```

### Q: Can I change the multi-login setting after initialization?

A: No, the `multiLogin` setting is fixed at initialization time. To change it, you need to restart your application with the new configuration. This ensures consistent behavior across all user sessions.

### Q: How do I add support for a new language?

A: You can add support for new languages using the `addMessages` method with the `ErrorMessageKeys` enum:

```javascript
const { ErrorMessageKeys } = require("superjwt");

// Add Japanese support using enums
auth.addMessages("ja", {
  [ErrorMessageKeys.PREVIOUS_SESSIONS_LOGGED_OUT]:
    "前のセッションは新しいログインによりログアウトされました",
  [ErrorMessageKeys.SINGLE_DEVICE_ONLY]:
    "セキュリティ上の理由により、1つのデバイスのみ許可されています",
  [ErrorMessageKeys.INVALID_TOKEN]: "無効なトークンです",
  [ErrorMessageKeys.TOKEN_EXPIRED]: "トークンの有効期限が切れました",
  [ErrorMessageKeys.UNAUTHORIZED]: "認証が必要です",
  [ErrorMessageKeys.FORBIDDEN]: "アクセスが禁止されています",
  [ErrorMessageKeys.NOT_FOUND]: "リソースが見つかりません",
  [ErrorMessageKeys.INTERNAL_ERROR]: "内部サーバーエラー",
});

// Use the new language with enum
auth.setLocale("ja");
const message = auth.getErrorMessage(
  ErrorMessageKeys.PREVIOUS_SESSIONS_LOGGED_OUT
);
```

### Q: Can I override specific error messages?

A: Yes, you can override specific error messages using the `errorMessages` configuration with the `ErrorMessageKeys` enum:

```javascript
const { createAuth, ErrorMessageKeys } = require("superjwt");

const auth = createAuth({
  secret: process.env.JWT_SECRET,
  errorMessages: {
    [ErrorMessageKeys.PREVIOUS_SESSIONS_LOGGED_OUT]: "Your custom message here",
    [ErrorMessageKeys.SINGLE_DEVICE_ONLY]: "Custom single device message",
    [ErrorMessageKeys.INVALID_TOKEN]: "Custom invalid token message",
    [ErrorMessageKeys.UNAUTHORIZED]: "Custom unauthorized message",
    [ErrorMessageKeys.FORBIDDEN]: "Custom forbidden message",
    [ErrorMessageKeys.NOT_FOUND]: "Custom not found message",
    [ErrorMessageKeys.INTERNAL_ERROR]: "Custom internal error message",
  },
});
```

### Q: How do I detect user locale automatically?

A: You can detect user locale from request headers:

```javascript
app.use((req, res, next) => {
  const locale =
    req.headers["accept-language"]?.split(",")[0]?.split("-")[0] || "en";
  auth.setLocale(locale);
  next();
});
```

### Q: Why should I use ErrorMessageKeys enum instead of strings?

A: Using the `ErrorMessageKeys` enum provides several benefits:

**Type Safety:**

```javascript
// ❌ String literals - no type safety
const message = auth.getErrorMessage("INVALID_TOKIN"); // Typo, no error

// ✅ Enum - TypeScript catches typos
const message = auth.getErrorMessage(ErrorMessageKeys.INVALID_TOKIN); // TypeScript error
```

**Autocomplete:**

```javascript
// ✅ IDE provides autocomplete for all available keys
const message = auth.getErrorMessage(ErrorMessageKeys.INVALID_TOKEN); // Autocomplete works
```

**Consistency:**

```javascript
// ✅ Same enum used everywhere
const config = {
  errorMessages: {
    [ErrorMessageKeys.INVALID_TOKEN]: "Custom message",
  },
};

const message = auth.getErrorMessage(ErrorMessageKeys.INVALID_TOKEN);
```

**Refactoring:**

```javascript
// ✅ Easy to rename keys across entire codebase
// Just change the enum value and all references update automatically
```

// PostgreSQL example
async function getUserByEmail(email) {
const result = await db.query("SELECT \* FROM users WHERE email = $1", [
email,
]);
return result.rows[0];
}

````

### Q: How does JWT blacklisting work?

A: JWT blacklisting allows you to invalidate tokens before they expire. JWT Auth Suite supports three storage backends:

- **Memory**: Fast but not persistent (good for development)
- **Redis**: Fast and persistent (recommended for production)
- **Database**: Persistent but slower (good for audit trails)

```javascript
// Blacklist a specific token
await auth.blacklistToken(token);

// Blacklist all tokens for a user
await auth.blacklistUser(userId);

// Check if token is blacklisted
const isBlacklisted = await auth.isTokenBlacklisted(token);
````

### Q: What is refresh token rotation?

A: Refresh token rotation enhances security by automatically generating new refresh tokens when the old ones are used. This prevents token reuse attacks:

```javascript
// Enable refresh token rotation
const auth = createAuth({
  secret: process.env.JWT_SECRET,
  enableRefreshRotation: true,
});

// Each refresh generates a new token pair
const result = await auth.rotateRefreshToken(oldRefreshToken, user);
// Returns: { accessToken, refreshToken, familyId }
```

### Q: How do I implement multi-tenancy?

A: JWT Auth Suite provides built-in multi-tenant support for SaaS applications:

```javascript
// Enable tenants
const auth = createAuth({
  secret: process.env.JWT_SECRET,
  enableTenants: true,
});

// Register tenants
auth.registerTenant("company1", {
  name: "Company 1",
  subdomain: "company1",
  domain: "company1.myapp.com",
});

// Use tenant middleware
app.use(auth.tenantMiddleware.resolveTenant());
```

### Q: How secure is the password hashing?

A: JWT Auth Suite uses bcrypt with configurable salt rounds (default: 12). It also includes password strength validation:

```javascript
// Hash password with custom salt rounds
const hashedPassword = await auth.hashPassword(password);

// Validate password strength
const validation = auth.validatePassword(password);
if (!validation.valid) {
  console.log(validation.errors); // ['Password must be at least 8 characters']
}

// Check password strength score
const strength = auth.checkPasswordStrength(password);
// Returns: { score: 85, level: 'Strong', feedback: [] }
```

## Contributing

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add some amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## License

MIT License - see [LICENSE](LICENSE) file for details.

## Performance & Scalability

### 🚀 **Performance Optimization**

#### **Token Verification Performance**

```javascript
// ✅ Use Redis for token blacklist in production
const auth = createAuth({
  secret: process.env.JWT_SECRET,
  redisClient: redis, // Use Redis instead of memory
  roles: ["user"],
});

// ✅ Cache user data to avoid database hits
const userCache = new Map();

app.get("/profile", auth.protect(), async (req, res) => {
  const userId = req.user.sub;

  // Check cache first
  let user = userCache.get(userId);
  if (!user) {
    user = await getUserFromDatabase(userId);
    userCache.set(userId, user);
  }

  res.json({ user });
});
```

#### **Rate Limiting Performance**

```javascript
// ✅ Use Redis for distributed rate limiting
const auth = createAuth({
  secret: process.env.JWT_SECRET,
  enableRateLimiting: true,
  rateLimitStorage: "redis", // Better than memory for multiple servers
  roles: ["user"],
});

// ✅ Optimize rate limiting keys
const customRateLimiter = new RateLimiter({
  windowMs: 15 * 60 * 1000,
  maxAttempts: 100,
  keyGenerator: (req) => {
    // Use user ID if authenticated, IP if not
    return req.user ? `user:${req.user.sub}` : `ip:${req.ip}`;
  },
});
```

#### **Database Optimization**

```javascript
// ✅ Use connection pooling
const auth = createAuth({
  secret: process.env.JWT_SECRET,
  prismaClient: prisma, // Prisma handles connection pooling
  roles: ["user"],
});

// ✅ Batch database operations
app.post("/bulk-action", auth.protect(), async (req, res) => {
  const { userIds } = req.body;

  // Batch update instead of individual queries
  await prisma.user.updateMany({
    where: { id: { in: userIds } },
    data: { lastActive: new Date() },
  });

  res.json({ success: true });
});
```

### 📊 **Monitoring & Metrics**

#### **Performance Metrics**

```javascript
// ✅ Track authentication performance
const auth = createAuth({
  secret: process.env.JWT_SECRET,
  enableMetrics: true,
  metricsConfig: {
    enableConsoleMetrics: true,
    enableFileMetrics: true,
    collectionInterval: 30000, // 30 seconds
    remoteEndpoint: "https://your-monitoring.com/metrics",
  },
  roles: ["user"],
});

// ✅ Custom performance tracking
app.use((req, res, next) => {
  const start = Date.now();

  res.on("finish", () => {
    const duration = Date.now() - start;
    auth.metrics.timer("request_duration", duration, {
      method: req.method,
      route: req.route?.path || req.path,
      status: res.statusCode,
    });
  });

  next();
});
```

#### **Memory Usage Optimization**

```javascript
// ✅ Clean up expired tokens regularly
setInterval(async () => {
  await auth.blacklist.cleanupExpiredTokens();
}, 60 * 60 * 1000); // Every hour

// ✅ Limit cache size
const userCache = new Map();
const MAX_CACHE_SIZE = 1000;

function setCachedUser(userId, user) {
  if (userCache.size >= MAX_CACHE_SIZE) {
    // Remove oldest entry
    const firstKey = userCache.keys().next().value;
    userCache.delete(firstKey);
  }
  userCache.set(userId, user);
}
```

### 🔄 **Scalability Patterns**

#### **Horizontal Scaling**

```javascript
// ✅ Use Redis for shared state
const redis = require("redis");
const client = redis.createClient({
  host: process.env.REDIS_HOST,
  port: process.env.REDIS_PORT,
});

const auth = createAuth({
  secret: process.env.JWT_SECRET,
  redisClient: client,
  enableRateLimiting: true,
  rateLimitStorage: "redis",
  roles: ["user"],
});

// ✅ Load balance with sticky sessions disabled
// ✅ Use JWT for stateless authentication
// ✅ Share rate limiting state across instances
```

#### **Microservices Architecture**

```javascript
// ✅ Service A: Authentication Service
const authService = createAuth({
  secret: process.env.JWT_SECRET,
  roles: ["user", "admin"],
  enableRateLimiting: true,
});

// ✅ Service B: Business Logic Service
const businessService = createAuth({
  secret: process.env.JWT_SECRET, // Same secret for token verification
  roles: ["user", "admin"],
});

// ✅ Verify tokens across services
app.get("/api/data", businessService.protect(), (req, res) => {
  // Token verified by business service
  res.json({ data: "sensitive data" });
});
```

### ⚡ **Performance Best Practices**

#### **Do's**

```javascript
// ✅ Use connection pooling
// ✅ Cache frequently accessed data
// ✅ Use Redis for distributed state
// ✅ Monitor performance metrics
// ✅ Clean up expired data regularly
// ✅ Use appropriate rate limiting
// ✅ Optimize database queries
```

#### **Don'ts**

```javascript
// ❌ Don't store large objects in JWT
// ❌ Don't use memory storage in production
// ❌ Don't ignore performance metrics
// ❌ Don't skip cleanup routines
// ❌ Don't use weak rate limiting
// ❌ Don't make unnecessary database calls
```

## Troubleshooting

### Common Issues

#### ❌ "Invalid token" Error

```javascript
// ❌ Wrong - Missing Bearer prefix
const token = req.headers.authorization;

// ✅ Correct - Extract token properly
const token = req.headers.authorization?.replace("Bearer ", "");
```

#### ❌ "Token expired" Error

```javascript
// ❌ Wrong - Token expired
const token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...";

// ✅ Correct - Generate new token
const token = auth.generateToken({
  sub: "user123",
  role: "user",
});
```

#### ❌ "Role not found" Error

```javascript
// ❌ Wrong - Role not defined in config
const auth = initAuth({
  secret: "secret",
  roles: ["user"], // Missing "admin" role
});

// ✅ Correct - Define all roles you'll use
const auth = initAuth({
  secret: "secret",
  roles: ["admin", "user", "moderator"],
});
```

#### ❌ "Secret too weak" Error

```javascript
// ❌ Wrong - Weak secret
const auth = initAuth({
  secret: "123", // Too short and weak
  roles: ["user"],
});

// ✅ Correct - Strong secret (32+ characters)
const auth = initAuth({
  secret: "your-super-secret-key-that-is-at-least-32-characters-long",
  roles: ["user"],
});
```

### Debug Mode

Enable debug mode to see what's happening:

```javascript
const auth = initAuth({
  secret: "your-secret",
  roles: ["user"],
  debug: true, // Enable debug logging
});
```

### Still Having Issues?

1. **Check your token format**: Should be `Bearer <token>`
2. **Verify your secret**: Must be at least 32 characters
3. **Check token expiry**: Default is 15 minutes
4. **Enable debug mode**: See detailed error messages
5. **Check the console**: Look for error messages

## Quick Reference

### initAuth vs createAuth

| Need                   | Use          | Example                   |
| ---------------------- | ------------ | ------------------------- |
| **Simple JWT auth**    | `initAuth`   | Basic login/logout        |
| **Production app**     | `createAuth` | Enterprise features       |
| **Learning/Prototype** | `initAuth`   | Quick setup               |
| **SaaS platform**      | `createAuth` | Multi-tenant support      |
| **High traffic**       | `createAuth` | Rate limiting required    |
| **Compliance**         | `createAuth` | Security logging required |

### Rate Limiter Types

| Type            | Limit     | Use Case               |
| --------------- | --------- | ---------------------- |
| `login`         | 5/15min   | Prevent brute force    |
| `passwordReset` | 3/hour    | Prevent spam           |
| `tokenRefresh`  | 10/min    | Prevent abuse          |
| `api`           | 100/15min | General API protection |

### Middleware Order

```javascript
// ✅ Correct order
app.use(express.json()); // 1. Parse JSON
app.use(auth.securityLogger.createMiddleware()); // 2. Security logging
app.use(auth.metrics.createRequestMetricsMiddleware()); // 3. Metrics
app.use(auth.rateLimiter.api.createMiddleware()); // 4. Rate limiting
app.use(auth.protect()); // 5. Authentication
app.use(auth.requireRole("admin")); // 6. Authorization
```

### Common Patterns

```javascript
// Public route
app.post("/login", auth.rateLimiter.login.createMiddleware(), handler);

// Protected route
app.get(
  "/profile",
  auth.rateLimiter.api.createMiddleware(),
  auth.protect(),
  handler
);

// Admin route
app.get(
  "/admin",
  auth.rateLimiter.api.createMiddleware(),
  auth.requireRole("admin"),
  handler
);

// Sensitive route
app.post(
  "/change-password",
  auth.rateLimiter.passwordReset.createMiddleware(),
  auth.protect(),
  handler
);
```

### ErrorMessageKeys Reference

```javascript
const { ErrorMessageKeys } = require("superjwt");

// Multi-login specific keys
ErrorMessageKeys.MULTI_LOGIN_DISABLED;
ErrorMessageKeys.PREVIOUS_SESSIONS_LOGGED_OUT;
ErrorMessageKeys.SINGLE_DEVICE_ONLY;
ErrorMessageKeys.DEVICE_LIMIT_EXCEEDED;

// General authentication keys
ErrorMessageKeys.INVALID_TOKEN;
ErrorMessageKeys.TOKEN_EXPIRED;
ErrorMessageKeys.INVALID_CREDENTIALS;
ErrorMessageKeys.ACCESS_DENIED;
ErrorMessageKeys.RATE_LIMIT_EXCEEDED;
ErrorMessageKeys.UNAUTHORIZED;
ErrorMessageKeys.FORBIDDEN;
ErrorMessageKeys.NOT_FOUND;
ErrorMessageKeys.INTERNAL_ERROR;
```

## Roadmap

- [x] JWT Blacklisting
- [x] Multi-tenant support
- [x] Password hashing utilities
- [x] Refresh token rotation
- [x] Rate limiting integration
- [x] Security logging and monitoring
- [x] Metrics collection
- [ ] CLI for secret generation
- [ ] Framework adapters (Fastify, Koa, NestJS)
- [ ] Multiple roles per user
- [ ] Role hierarchy support
- [ ] Token analytics and monitoring
- [ ] Webhook support for security events
