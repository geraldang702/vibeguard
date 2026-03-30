---
name: harden
description: "Proactively harden a project's security beyond fixing known issues. Adds security middleware, headers, input validation, .env.example, lint rules, and strips console.logs. Must be invoked manually. Run /vibeguard:audit first to understand the project."
argument-hint: "[headers|middleware|validation|env|logs|deps]"
disable-model-invocation: true
---

# VibeGuard Security Hardening

Proactively add security infrastructure to this project. This goes beyond fixing specific vulnerabilities — it adds defense-in-depth layers.

## Focus Area

If the user specified a focus: "$ARGUMENTS"

- `headers` → security headers only
- `middleware` → security middleware stack
- `validation` → input validation on all endpoints
- `env` → environment variable cleanup and .env.example
- `logs` → strip/gate console.logs
- `deps` → dependency audit and lockfile
- Empty → full hardening (present plan first)

## Before Doing Anything: Present the Plan

Show the user what you'll add BEFORE adding it:

```
## Hardening Plan

I'll add the following to your project:

1. **Security middleware** — helmet, cors (restricted), rate-limit
2. **Security headers** — CSP, HSTS, X-Frame-Options, Referrer-Policy, Permissions-Policy
3. **Input validation** — zod schemas on all API endpoints
4. **Environment cleanup** — .env.example with all required vars, verify .gitignore
5. **Console.log cleanup** — remove or gate behind NODE_ENV
6. **Error handling** — production error handler that hides internals
7. **Lint rules** — eslint-plugin-security (if eslint present)

Proceed with all, or pick specific numbers?
```

Wait for approval before proceeding.

## Hardening Checklist

### 1. Security Middleware Stack

For Express/Node.js:
```javascript
// SECURITY (vibeguard): Security middleware stack
const helmet = require('helmet');
const cors = require('cors');
const rateLimit = require('express-rate-limit');

app.use(helmet());
app.use(cors({ origin: process.env.ALLOWED_ORIGINS?.split(','), credentials: true }));
app.use('/api/auth', rateLimit({ windowMs: 15 * 60 * 1000, max: 10 }));
app.use('/api', rateLimit({ windowMs: 60 * 1000, max: 100 }));
```

For Next.js: add security headers in `next.config.js` and middleware.

### 2. Input Validation

Add zod/joi schemas to every API endpoint that accepts input. Create a shared validation middleware pattern.

### 3. Environment Variables

- Create `.env.example` listing every required env var with placeholder values
- Verify `.env`, `.env.local`, `.env.production` are in `.gitignore`
- Check for `NEXT_PUBLIC_`/`VITE_` prefix on secret values

### 4. Console.log Cleanup

- Remove all `console.log` statements, OR
- Replace with a structured logger (pino/winston) that:
  - Redacts sensitive fields (password, token, secret, key, authorization)
  - Is disabled in production or set to appropriate log level
  - Uses JSON format for log aggregation

### 5. Production Error Handler

Add a catch-all error handler that returns generic messages to clients and logs details server-side only.

### 6. Security Lint Rules

If eslint is present, add `eslint-plugin-security` with relevant rules enabled.

### 7. Git Security

- Ensure `.gitignore` covers: `.env*`, `node_modules/`, `.next/`, `dist/`, `.cursor/`, `.copilot/`, `*.pem`
- Add `.dockerignore` if Dockerfile exists
- Suggest pre-commit hooks (husky + detect-secrets)

## After Hardening

Present a summary of everything that was added, new dependencies to install, and any manual steps the user needs to take (like setting actual env var values).
