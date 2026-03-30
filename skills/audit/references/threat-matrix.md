# VibeGuard Threat Matrix — Complete Vulnerability Reference

> 24 categories, 170+ checks. Every vulnerability pattern, how to detect it, how to fix it.

---

## TABLE OF CONTENTS
1. Injection Attacks
2. Cross-Site Scripting (XSS)
3. Authentication & Session Management
4. Authorization & Access Control
5. Rate Limiting & Abuse Prevention
6. CSRF
7. Security Headers
8. Data Exposure & Privacy
9. File Upload Vulnerabilities
10. Dependency & Supply Chain
11. Cryptography
12. Denial of Service
13. WebSocket Security
14. Deployment & Infrastructure
15. API Security
16. Client-Side Security
17. Email Security
18. Next.js / React-Specific (including App Router)
19. Database Security
20. Server-Side Request Forgery (SSRF)
21. Race Conditions & TOCTOU
22. Webhook & Payment Security
23. Vibe-Coding-Specific Antipatterns
24. Auth Provider Misconfigurations (NextAuth, Clerk, Auth.js, Lucia)

---

## 1. INJECTION ATTACKS

### 1.1 SQL Injection
- **Detect**: String concatenation/interpolation in SQL: `"SELECT * FROM users WHERE id = " + id`, template literals with SQL keywords, `Prisma.$queryRawUnsafe()`, `Sequelize.literal()`, Django `.raw()` without params, Flask `text()` without bind params
- **Fix**: Parameterized queries / prepared statements. For ORMs, use parameter binding in raw queries.

### 1.2 NoSQL Injection
- **Detect**: `req.body`/`req.query` passed directly to `.find()`, `.findOne()`, `.updateOne()`, `.deleteMany()` — allows `$gt`, `$ne`, `$regex` operators
- **Fix**: Validate input schema, cast types, strip `$`-prefixed keys. Use `mongo-sanitize`.

### 1.3 Command Injection
- **Detect**: User input in `exec()`, `spawn()`, `system()`, `os.system()`, `subprocess.run(shell=True)`, backticks
- **Fix**: Use array-based args (`execFile`, `subprocess.run([...])`), escape inputs, use allowlists.

### 1.4 LDAP Injection
- **Detect**: User input in LDAP filter strings via interpolation
- **Fix**: Escape special chars `()*\NUL`

### 1.5 Header Injection / CRLF
- **Detect**: User input in `res.setHeader()`, `res.writeHead()`, redirect URLs without stripping `\r\n`
- **Fix**: Strip/reject `\r\n` from user-controlled header values

### 1.6 Log Injection
- **Detect**: `console.log()`, `logger.info()` with raw user input containing newlines
- **Fix**: Sanitize log inputs, strip newlines, use structured logging (JSON)

### 1.7 Template Injection (SSTI)
- **Detect**: User input as template source: `render_template_string(user_input)` (Flask), `ejs.render(user_input)` (Express)
- **Fix**: Pass user input as data, never as template. Use sandboxed environments.

### 1.8 GraphQL Injection
- **Detect**: Missing query depth limits, introspection enabled in prod, no complexity analysis, no rate limiting
- **Fix**: Add `graphql-depth-limit`, disable introspection in prod, add complexity analysis, use persisted queries

### 1.9 XPath Injection
- **Detect**: User input in XPath expressions via concatenation
- **Fix**: Parameterized XPath or sanitize input

---

## 2. CROSS-SITE SCRIPTING (XSS)

### 2.1 Reflected XSS
- **Detect**: `req.query`, `req.params`, `searchParams` inserted into HTML without encoding, used in `res.send()`/`res.write()` with HTML
- **Fix**: HTML-encode all output, auto-escaping templates, `textContent` instead of `innerHTML`

### 2.2 Stored XSS
- **Detect**: DB-sourced data rendered via `innerHTML`, `dangerouslySetInnerHTML`, `v-html`, `[innerHTML]`, `{@html}`
- **Fix**: Sanitize with DOMPurify on output, add CSP headers

### 2.3 DOM-Based XSS
- **Detect**: `location.hash`, `location.search`, `document.referrer`, `postMessage` data flowing to `innerHTML`, `document.write()`, `eval()`
- **Fix**: Validate/sanitize DOM sources, use `textContent`, validate `postMessage` origins

### 2.4 React/Framework XSS
- **Detect**: `dangerouslySetInnerHTML={{__html: variable}}` where variable is user-sourced; `href={userInput}` without protocol check (allows `javascript:`)
- **Fix**: DOMPurify before `dangerouslySetInnerHTML`, validate URLs start with `http://`/`https://`

### 2.5 SVG XSS
- **Detect**: SVG uploads served as `image/svg+xml` without sanitization (can contain `<script>` and event handlers)
- **Fix**: Strip scripts/handlers from SVGs server-side, serve with `Content-Disposition: attachment`, or rasterize

---

## 3. AUTHENTICATION & SESSION MANAGEMENT

### 3.1 Hardcoded Credentials/Secrets
- **Detect**: Regex for API key patterns (`sk-*`, `AKIA*`, `ghp_*`, `xoxb-*`, `Bearer ey...`), `password = "..."`, connection strings with creds, `BEGIN RSA PRIVATE KEY`, base64 JWT secrets
- **Fix**: Move to env vars, `.env` in `.gitignore`, suggest secrets manager

### 3.2 Weak Password Policy
- **Detect**: Signup handlers missing password validation logic
- **Fix**: Min 8 chars, `zxcvbn` for strength, HaveIBeenPwned check

### 3.3 Plaintext/Weak Password Hashing
- **Detect**: Password stored without bcrypt/scrypt/argon2, using `md5()`/`sha1()`/`sha256()` for passwords
- **Fix**: bcrypt (cost ≥10), scrypt, or argon2id

### 3.4 Insecure Session Config
- **Detect**: Missing cookie flags (httpOnly, secure, sameSite), memory session store in prod, no expiration, no session rotation on login
- **Fix**: `httpOnly: true`, `secure: true`, `sameSite: 'lax'`, server-side store (Redis), regenerate on login

### 3.5 JWT Misuse
- **Detect**: `alg: "none"` accepted, secret <32 chars, no `expiresIn`, sensitive data in payload, hardcoded secret
- **Fix**: Enforce algorithm `{ algorithms: ['HS256'] }`, 256-bit+ secrets, set expiration, RS256 for distributed

### 3.6 Broken Password Reset
- **Detect**: `Math.random()` for reset tokens, no expiration, token not single-use, user enumeration via different responses
- **Fix**: `crypto.randomBytes(32)`, 1-hour expiry, single-use, identical response regardless of email existence

### 3.7 OAuth Misconfiguration
- **Detect**: Missing `state` parameter, no nonce, overly broad scopes, redirect URI not validated against allowlist
- **Fix**: Generate/validate `state`, use `nonce`, minimum scopes, strict redirect URI allowlist

### 3.8 Session Not Invalidated on Password Change
- **Detect**: Password change handler doesn't destroy other active sessions
- **Fix**: Invalidate all sessions except current on password change, force re-auth

### 3.9 Email Enumeration
- **Detect**: Login/reset returns different messages for existing vs non-existing accounts ("user not found" vs "wrong password")
- **Fix**: Return identical generic message regardless ("Invalid credentials" / "If an account exists, a reset email has been sent")

---

## 4. AUTHORIZATION & ACCESS CONTROL

### 4.1 Missing Auth on Routes
- **Detect**: Map all routes, check which have auth middleware. Flag admin/API/data routes missing auth. Check middleware ordering.
- **Fix**: Auth middleware on all non-public routes

### 4.2 IDOR / Broken Object-Level Auth (BOLA)
- **Detect**: DB queries using `req.params.id` WITHOUT `WHERE user_id = currentUser.id`. Sequential/predictable IDs.
- **Fix**: Always filter by authenticated user's ID, use UUIDs instead of sequential IDs

### 4.3 Missing Function-Level Auth
- **Detect**: Admin routes (user management, config, export) without role/permission checks
- **Fix**: Role-based middleware, check permissions before privileged operations

### 4.4 Mass Assignment / Privilege Escalation
- **Detect**: `Object.assign()`, `{...req.body}`, `.create(req.body)`, `.update(req.body)` — user can set `role: "admin"` or `isAdmin: true`
- **Fix**: Explicit field picking: `{ name: req.body.name, email: req.body.email }`, ORM allowlists

### 4.5 Path Traversal
- **Detect**: `fs.readFile()`, `res.sendFile()`, `path.join()` with user input without `..` check
- **Fix**: `path.resolve()` + verify within allowed directory, reject `..` sequences

### 4.6 Insecure File Name Handling
- **Detect**: Original upload filename used for storage path
- **Fix**: UUID-based names, strip path components, validate extensions

### 4.7 Soft-Delete Data Leaks
- **Detect**: Soft-deleted records (e.g. `deleted_at IS NOT NULL`) still returned by API queries that don't filter for deletion status
- **Fix**: Add `WHERE deleted_at IS NULL` to all queries, or use a global scope/filter. Verify in Supabase RLS policies too.

---

## 5. RATE LIMITING & ABUSE PREVENTION

### 5.1 No Rate Limit on Auth
- **Detect**: Login/register/reset endpoints without rate limiting middleware
- **Fix**: Login: 5-10/15min per IP+username. Register: 3-5/hr per IP. Reset: 3-5/hr per email.

### 5.2 No Rate Limit on API
- **Detect**: Missing global or per-route rate limiting
- **Fix**: General: 100/min. Expensive ops: 10-20/min. Uploads: 5/min.

### 5.3 No Rate Limit on File Uploads
- **Detect**: Upload routes without rate limits and file size limits
- **Fix**: Rate limits + max file size + total storage per user

### 5.4 Missing Bot Protection
- **Detect**: Public forms without CAPTCHA or anti-automation
- **Fix**: reCAPTCHA/hCaptcha/Turnstile + honeypot fields

### 5.5 No Account Lockout
- **Detect**: Login handler missing failed attempt tracking/lockout
- **Fix**: Progressive delay or temp lockout after 5-10 fails, notify account owner

### 5.6 Missing Request Size Limits
- **Detect**: No body parser limits (`express.json({ limit })`, `nginx client_max_body_size`)
- **Fix**: 1MB JSON, 10-50MB uploads

### 5.7 Missing Pagination / Unbounded Queries
- **Detect**: `SELECT *` without `LIMIT`, list endpoints returning all records
- **Fix**: Default + max page size, cursor-based pagination

---

## 6. CSRF

### 6.1 Missing CSRF Protection
- **Detect**: POST/PUT/DELETE endpoints without CSRF tokens or SameSite cookies
- **Fix**: CSRF middleware + tokens in forms + `SameSite: 'lax'`/'strict'`. For SPAs: SameSite cookies + Origin/Referer check.

### 6.2 CSRF Token in GET Requests
- **Detect**: CSRF tokens in URL query params (logged, cached)
- **Fix**: Tokens in POST body or custom headers only

---

## 7. SECURITY HEADERS

### 7.1 Missing CSP
- **Detect**: No `Content-Security-Policy` header
- **Fix**: `default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; font-src 'self'`

### 7.2 Missing X-Content-Type-Options
- **Fix**: `X-Content-Type-Options: nosniff`

### 7.3 Missing X-Frame-Options
- **Fix**: `X-Frame-Options: DENY` or CSP `frame-ancestors 'none'`

### 7.4 Missing HSTS
- **Fix**: `Strict-Transport-Security: max-age=31536000; includeSubDomains`

### 7.5 Missing Referrer-Policy
- **Fix**: `Referrer-Policy: strict-origin-when-cross-origin`

### 7.6 Missing Permissions-Policy
- **Fix**: `Permissions-Policy: camera=(), microphone=(), geolocation=()`

### 7.7 Overly Permissive CORS
- **Detect**: `Access-Control-Allow-Origin: *` with credentials, reflecting `req.headers.origin` without validation
- **Fix**: Explicit origin allowlist, never `*` with credentials

### 7.8 Missing Cache-Control on Sensitive Pages
- **Fix**: `Cache-Control: no-store, no-cache, must-revalidate, private` on sensitive endpoints

### 7.9 Tech Stack Disclosure
- **Detect**: `X-Powered-By: Express`, `Server: Apache/2.4.1`
- **Fix**: `app.disable('x-powered-by')`, strip `Server` header

---

## 8. DATA EXPOSURE & PRIVACY

### 8.1 Verbose Errors in Prod
- **Detect**: `err.stack` or `err.message` sent to client, `NODE_ENV` not checked, debug mode not disabled
- **Fix**: Generic messages to client, detailed logs server-side only, `NODE_ENV=production`

### 8.2 API Over-Exposure
- **Detect**: `res.json(user)` returning full DB objects (password hashes, internal IDs, PII)
- **Fix**: DTOs/serializers, explicitly pick return fields

### 8.3 Sensitive Data in localStorage
- **Detect**: `localStorage.setItem()` with tokens/PII (accessible via XSS)
- **Fix**: httpOnly cookies for auth tokens, minimize client storage

### 8.4 Sensitive Data in URLs
- **Detect**: Tokens, passwords, PII in query parameters
- **Fix**: POST bodies or headers for sensitive data

### 8.5 Exposed .env / Config Files
- **Detect**: `.env` in public dirs, missing from `.gitignore`, `.git/` accessible via web
- **Fix**: `.gitignore`, deny dotfile access in web server

### 8.6 Source Maps in Prod
- **Detect**: `.map` files in production build output
- **Fix**: Disable source maps in prod or restrict access

### 8.7 Debug/Dev Endpoints in Prod
- **Detect**: `/debug`, `/test`, `/api/docs`, `/graphql/playground`, `/__debug__` routes not gated behind env check
- **Fix**: Gate behind `NODE_ENV !== 'production'`

### 8.8 Console.log Leaking Secrets
- **Detect**: `console.log(req.body)` (may contain passwords), `console.log(user)` (full user object with hash), `console.log(token)`, `console.log(error)` (stack traces in browser), any `console.*` in production code that outputs sensitive variables
- **Fix**: Remove all `console.log` from production code or gate behind env. Use structured logger (pino/winston) that redacts sensitive fields. Add ESLint `no-console` rule.

### 8.9 Frontend Env Var Prefix Leaks
- **Detect**: Secret keys using `NEXT_PUBLIC_` (Next.js), `VITE_` (Vite), `REACT_APP_` (CRA), `NUXT_PUBLIC_` (Nuxt 3) prefixes — these get bundled into client-side JavaScript. Examples: `NEXT_PUBLIC_STRIPE_SECRET_KEY`, `VITE_DATABASE_URL`, `REACT_APP_SUPABASE_SERVICE_ROLE_KEY`
- **Fix**: Only public/non-secret values should use these prefixes. Secret keys should NEVER have a public prefix. Move API calls to server-side routes/actions.

### 8.10 EXIF/Metadata Leaks in Uploads
- **Detect**: User-uploaded images stored/served without stripping EXIF data — can contain GPS coordinates, device info, timestamps
- **Fix**: Strip EXIF data server-side before storage using `sharp` (Node.js) or `Pillow` (Python). `sharp(image).rotate().toBuffer()` strips EXIF by default.

### 8.11 Git History Contains Secrets
- **Detect**: `.env` or config with secrets was committed and later removed (still in git history)
- **Fix**: Rotate all exposed secrets immediately. Use `git filter-branch` or BFG Repo-Cleaner. Add pre-commit hooks (e.g., `detect-secrets`, `gitleaks`).

---

## 9. FILE UPLOAD VULNERABILITIES

### 9.1 Unrestricted File Types
- **Detect**: No file type validation, or extension-only check (bypassable)
- **Fix**: Allowlist extensions AND MIME types, check magic bytes, random filenames

### 9.2 Missing File Size Limits
- **Detect**: No multer limits, no nginx `client_max_body_size`
- **Fix**: Appropriate limits per upload type

### 9.3 Files Served from Same Origin
- **Detect**: Uploads served from main domain (cookie theft via upload XSS)
- **Fix**: Separate domain/CDN, `Content-Disposition: attachment`, `X-Content-Type-Options: nosniff`

---

## 10. DEPENDENCY & SUPPLY CHAIN

### 10.1 Known Vulnerable Deps
- **Detect**: `npm audit` / `pip-audit` / `safety check`
- **Fix**: Update vulnerable packages, suggest alternatives

### 10.2 Wildcard Versions
- **Detect**: `"*"`, `"latest"`, overly broad ranges in package.json
- **Fix**: Pin exact versions, commit lockfiles, use `npm ci`

### 10.3 Missing Lockfile
- **Detect**: No `package-lock.json`/`yarn.lock`/`pnpm-lock.yaml`
- **Fix**: Generate and commit

### 10.4 Missing Subresource Integrity (SRI)
- **Detect**: `<script src="https://cdn.example.com/lib.js">` without `integrity` attribute
- **Fix**: Add `integrity="sha384-..."` and `crossorigin="anonymous"` to all CDN script/style tags

---

## 11. CRYPTOGRAPHY

### 11.1 Weak Random for Security
- **Detect**: `Math.random()` for tokens/IDs/sessions/CSRF. `random.random()` in Python.
- **Fix**: `crypto.randomBytes()`, `crypto.randomUUID()`, Python `secrets` module

### 11.2 Weak/Obsolete Algorithms
- **Detect**: DES, 3DES, RC4, MD5, SHA1 for security purposes
- **Fix**: AES-256-GCM, SHA-256+, argon2id/bcrypt for passwords

### 11.3 Hardcoded IVs/Nonces
- **Detect**: Static IV values in encryption code
- **Fix**: Random IV per operation, store IV with ciphertext

### 11.4 Timing Attacks on Secret Comparison
- **Detect**: `===` or `==` used to compare secrets, tokens, hashes, API keys (short-circuits on first mismatch, leaking length info)
- **Fix**: Use `crypto.timingSafeEqual()` (Node.js) or `hmac.compare_digest()` (Python) for constant-time comparison

### 11.5 Missing HTTPS
- **Detect**: `http://` in API URLs, no TLS config, no HTTP→HTTPS redirect
- **Fix**: HTTPS everywhere, redirect HTTP, TLS 1.2+ only

---

## 12. DENIAL OF SERVICE

### 12.1 ReDoS
- **Detect**: Nested quantifiers `(a+)+`, overlapping alternation `(a|a)+`
- **Fix**: Simplify regexes, input length limits, RE2 engine, timeouts

### 12.2 Unbounded Operations
- **Detect**: Loops/recursion bounded by user input
- **Fix**: Hard limits, depth limits, timeouts

### 12.3 XML Bombs / Zip Bombs
- **Detect**: XML parsing without disabling external entities, zip extraction without size limits
- **Fix**: Disable XXE, limit extraction size, validate dimensions

### 12.4 Uncontrolled Memory
- **Detect**: `JSON.parse()` on unbounded input, loading full files to memory
- **Fix**: Size limits, streaming parsers

---

## 13. WEBSOCKET SECURITY

### 13.1 Missing WebSocket Auth
- **Detect**: WS connections accepted without token validation
- **Fix**: Validate auth token on connection

### 13.2 Missing Origin Validation
- **Detect**: No `Origin` header check on WS upgrade
- **Fix**: Validate against origin allowlist

### 13.3 Missing Message Validation
- **Fix**: Validate schema, sanitize, add size limits

### 13.4 Message Broadcast Without Sanitization
- **Detect**: Chat messages broadcast raw to other users
- **Fix**: Sanitize before broadcast, rate limit messages

---

## 14. DEPLOYMENT & INFRASTRUCTURE

### 14.1 Debug Mode in Prod
- **Detect**: Flask `debug=True`, Django `DEBUG=True`, Express stack traces
- **Fix**: Gate behind env var, `false` in production

### 14.2 Default Credentials
- **Detect**: `admin/admin`, `root/root`, `password`, `changeme`, `test123`
- **Fix**: Strong unique passwords per environment

### 14.3 Missing Env Separation
- **Detect**: No `NODE_ENV`/`FLASK_ENV` usage, single config for all environments
- **Fix**: Environment-based config, different secrets per env

### 14.4 Docker Security
- **Detect**: `USER root`, `FROM *:latest`, `ENV SECRET=`, missing `.dockerignore`
- **Fix**: Non-root user, pin versions, use build secrets, `.dockerignore` with `.env`/`.git`

### 14.5 Exposed Ports
- **Detect**: DB ports (3306, 5432, 27017), Redis (6379) bound to `0.0.0.0` in docker-compose
- **Fix**: Bind to `127.0.0.1` or Docker networks

---

## 15. API SECURITY

### 15.1 Missing Input Validation
- **Detect**: No zod/joi/yup/pydantic validation on endpoints
- **Fix**: Schema validation middleware on all endpoints

### 15.2 Batch Endpoint Abuse
- **Detect**: Bulk endpoints without item count limits
- **Fix**: Max 100 items per batch

### 15.3 Missing Request ID / Audit Trail
- **Fix**: UUID per request, log request IDs, audit log for sensitive ops

### 15.4 API Docs Exposed in Prod
- **Detect**: `/docs`, `/swagger`, `/api-docs` publicly accessible
- **Fix**: Gate behind auth or disable in production

---

## 16. CLIENT-SIDE SECURITY

### 16.1 Auth/Business Logic Client-Side Only
- **Detect**: Authorization checks, price calculations, feature flags enforced only in frontend
- **Fix**: Server-side enforcement, client-side only for UX

### 16.2 Prototype Pollution
- **Detect**: Deep merge/extend without filtering `__proto__`, `constructor`, `prototype`
- **Fix**: Safe merge utilities, block prototype keys

### 16.3 PostMessage Vulnerabilities
- **Detect**: `addEventListener('message')` without `event.origin` check; `postMessage(data, '*')`
- **Fix**: Validate `event.origin`, specify target origin

### 16.4 Open Redirects
- **Detect**: `res.redirect(req.query.next)` without validation
- **Fix**: Validate against allowlist, allow only relative paths or same-origin

---

## 17. EMAIL SECURITY

### 17.1 Header Injection
- **Detect**: User input in To/CC/Subject without sanitization
- **Fix**: Strip newlines, use email libraries with auto-escaping

---

## 18. NEXT.JS / REACT-SPECIFIC

### 18.1 Server Actions Without Auth
- **Detect**: Next.js Server Actions missing auth checks
- **Fix**: Auth check at top of every Server Action

### 18.2 Exposed Server-Side Props
- **Detect**: `getServerSideProps` returning sensitive data (ends up in page source as `__NEXT_DATA__`)
- **Fix**: Filter sensitive fields before return

### 18.3 Middleware Bypass
- **Detect**: `matcher` config too narrow, routes not covered
- **Fix**: Broad matchers with explicit exclusions

### 18.4 API Route Missing Method Check
- **Detect**: No `req.method` check in API routes
- **Fix**: Check method, return 405 for unsupported

### 18.5 Client Component Data Leaks
- **Detect**: Sensitive data in Server→Client Component props (serialized to HTML)
- **Fix**: Filter before passing, fetch sensitive data client-side with auth

### 18.6 Route Handler Auth (App Router)
- **Detect**: `app/api/*/route.ts` files with `GET`/`POST`/`PUT`/`DELETE` exports that don't check `auth()` or `getServerSession()` before accessing/modifying data
- **Fix**: Check auth at the top of every exported handler. Return 401 if no session.

### 18.7 Server Action Data Leaks via `useActionState`
- **Detect**: Server Actions returning full error objects, stack traces, or internal data in the state. `useActionState` makes the return value available in client JS.
- **Fix**: Return only sanitized messages. Never return raw errors, DB objects, or internal IDs from Server Actions.

### 18.8 `revalidatePath`/`revalidateTag` Without Auth
- **Detect**: API route or Server Action calls `revalidatePath()` or `revalidateTag()` without auth — allows attackers to purge cache on demand
- **Fix**: Gate revalidation behind authentication

### 18.9 Parallel Routes / Intercepting Routes Exposing Auth-Gated Content
- **Detect**: Parallel or intercepting routes that render content without checking auth independently (relying on parent layout auth which can be bypassed via direct URL access)
- **Fix**: Check auth in every parallel/intercepting route segment, not just the layout

---

## 19. DATABASE SECURITY

### 19.1 Default DB Credentials
- **Detect**: Common defaults in connection strings
- **Fix**: Strong unique passwords per env

### 19.2 DB Exposed to Internet
- **Detect**: DB port in public-facing deployment config
- **Fix**: Private network, connection pooler with auth

### 19.3 Missing DB Connection Encryption
- **Detect**: No SSL/TLS in connection config
- **Fix**: Enable SSL, verify certificates

### 19.4 Excessive DB Privileges
- **Detect**: App uses root/admin DB user
- **Fix**: Least-privilege user (SELECT/INSERT/UPDATE/DELETE on specific tables only)

---

## 20. SERVER-SIDE REQUEST FORGERY (SSRF)

### 20.1 Unvalidated URL Fetching
- **Detect**: User-provided URLs passed to `fetch()`, `axios()`, `http.get()`, `urllib`, `requests.get()` on the server without validation. Common in: link preview generators, webhook URL configs, image proxy/resize endpoints, import-from-URL features.
- **Fix**: Validate URL against allowlist of domains/protocols. Block private IPs (127.0.0.1, 10.x, 172.16-31.x, 192.168.x, 169.254.x, ::1, fc00::). Resolve DNS and check IP before fetching. Set timeouts. Disable redirects or re-validate after redirect.

### 20.2 DNS Rebinding
- **Detect**: URL validated at check time but DNS changes before fetch time
- **Fix**: Resolve DNS once, fetch by IP with Host header, or use SSRF-safe libraries

---

## 21. RACE CONDITIONS & TOCTOU

### 21.1 Double-Spending / Double-Submit
- **Detect**: Financial transactions, coupon redemptions, vote counting, inventory decrements using read-then-write patterns without locking
- **Fix**: Database-level atomic operations (`UPDATE ... SET balance = balance - $amount WHERE balance >= $amount`), optimistic locking with version fields, idempotency keys for API requests

### 21.2 TOCTOU File Operations
- **Detect**: Checking file permissions/existence then operating on file in separate step
- **Fix**: Use atomic file operations, lock files during operations

### 21.3 Registration Race
- **Detect**: Unique constraint checked via SELECT before INSERT (another request can insert between check and write)
- **Fix**: Use database UNIQUE constraints, handle duplicate key errors gracefully

---

## 22. WEBHOOK & PAYMENT SECURITY

### 22.1 Missing Webhook Signature Verification
- **Detect**: Webhook endpoints for Stripe, GitHub, Twilio, SendGrid, etc. that don't verify the signature header (`stripe-signature`, `X-Hub-Signature-256`, etc.)
- **Fix**: Always verify signatures using the provider's SDK: `stripe.webhooks.constructEvent(body, sig, secret)`. Use raw body (not parsed JSON) for verification.

### 22.2 Client-Side Price/Amount Manipulation
- **Detect**: Price, amount, discount, or total sent from client and trusted by server. `{ product: "widget", price: 0.01 }` in request body used directly for payment.
- **Fix**: Always calculate prices server-side from product IDs. Never trust client-provided amounts. Use Stripe Checkout or Payment Intents created server-side.

### 22.3 Webhook Replay Attacks
- **Detect**: No timestamp check on webhook payloads, no idempotency
- **Fix**: Check timestamp freshness (reject >5min old), store processed event IDs to prevent replay

### 22.4 Insecure Payment Flow
- **Detect**: Direct charges created from client-provided amounts instead of Stripe Checkout/Payment Intents
- **Fix**: Create payment intents server-side, use Stripe Checkout, never expose secret key client-side

---

## 23. VIBE-CODING-SPECIFIC ANTIPATTERNS

These are patterns specifically common in AI-generated code:

### 23.1 TODO/Placeholder Auth
- **Detect**: `// TODO: add authentication`, `// FIXME: check permissions`, middleware that does `next()` unconditionally, `isAuthenticated = true` hardcoded
- **Fix**: Implement actual auth or flag as critical

### 23.2 AI Tool Artifacts in Repo
- **Detect**: `.cursor/` directory containing conversation history/prompts (may include pasted secrets, architecture details), `.copilot/`, `.aider.chat.history.md`, `.bolt/` directories
- **Fix**: Add to `.gitignore`, remove from git history if committed

### 23.3 Copy-Paste Config Vulnerabilities
- **Detect**: Default Next.js/Vite/Express configs never hardened, CORS set to `*` from a tutorial, `trust proxy` not configured for rate limiting behind reverse proxy
- **Fix**: Review and harden all framework configs

### 23.4 Mock/Stub Code in Production
- **Detect**: `if (true)` auth checks, `return { user: { role: 'admin' } }` stubs, test users with known passwords in seed files, `// skip auth in dev` without env check
- **Fix**: Remove stubs, gate behind `NODE_ENV`, delete test seed data

### 23.5 Unused But Exposed Routes
- **Detect**: Generated CRUD routes where only some are needed (e.g., user-facing app has DELETE /api/users/:id exposed)
- **Fix**: Remove unused routes, add auth to remaining

### 23.6 Overgenerous CRUD
- **Detect**: Full CRUD generated for every model when only read is needed. Admin-level operations (delete all, bulk update) exposed without role checks.
- **Fix**: Only expose needed operations. Admin operations require admin role.

### 23.7 Missing .gitignore Entries
- **Detect**: `.env`, `.env.local`, `.env.production`, `node_modules/`, `.next/`, `dist/`, `.cursor/` not in `.gitignore`
- **Fix**: Add comprehensive `.gitignore`

### 23.8 Hardcoded Development URLs in Production Code
- **Detect**: `http://localhost:3000`, `http://127.0.0.1:8000` in production source, API base URLs not using env vars
- **Fix**: Use env vars for all URLs, add env-based config

---

## 24. AUTH PROVIDER MISCONFIGURATIONS

These are the auth solutions vibe-coders actually use. Each has its own footguns.

### 24.1 NextAuth/Auth.js: Missing `NEXTAUTH_SECRET`
- **Detect**: No `NEXTAUTH_SECRET` or `AUTH_SECRET` in env, or using a weak/default value. In development NextAuth works without it — in production it's critical for signing JWTs.
- **Fix**: Generate a strong secret: `openssl rand -base64 32`. Set in production env vars.

### 24.2 NextAuth/Auth.js: Exposed Session Data
- **Detect**: Custom `session` callback returning full user object from DB (password hash, internal IDs, roles) — this data is accessible via `/api/auth/session` and the `useSession()` hook client-side
- **Fix**: Only return fields the client needs: `{ id, name, email, image }`

### 24.3 NextAuth/Auth.js: Missing CSRF Protection on Custom Auth Pages
- **Detect**: Custom sign-in pages that POST directly without including the CSRF token from NextAuth
- **Fix**: Use the built-in `signIn()` function from `next-auth/react`, or include the CSRF token from the `/api/auth/csrf` endpoint

### 24.4 NextAuth/Auth.js: OAuth Callback URL Not Restricted
- **Detect**: Missing `NEXTAUTH_URL` in production, or callback URLs not validated — allows open redirect after auth
- **Fix**: Set `NEXTAUTH_URL` to your production domain. Configure allowed callback URLs in provider settings.

### 24.5 Clerk: Publishable Key vs Secret Key Confusion
- **Detect**: `CLERK_SECRET_KEY` (starts with `sk_`) used in client-side code, or assigned to a `NEXT_PUBLIC_` variable
- **Fix**: Client-side uses `NEXT_PUBLIC_CLERK_PUBLISHABLE_KEY` only. `CLERK_SECRET_KEY` is server-side only.

### 24.6 Clerk: Missing `clerkMiddleware()` on Protected Routes
- **Detect**: Routes that should require auth but aren't covered by `clerkMiddleware()` matcher config, or using `authMiddleware` (deprecated)
- **Fix**: Configure `clerkMiddleware()` with `createRouteMatcher()` covering all protected routes

### 24.7 Clerk: Trusting Client-Side `user.publicMetadata` for Authorization
- **Detect**: Role or permission checks using `user.publicMetadata.role` on the client without server-side verification — users can modify publicMetadata via Clerk's frontend API in some configurations
- **Fix**: Use `privateMetadata` (server-only) for roles/permissions, or verify against Clerk Backend API

### 24.8 Auth.js v5 / Lucia: Session Token in URL
- **Detect**: Session tokens passed as URL query parameters (logged by servers, browser history, referrers) instead of httpOnly cookies
- **Fix**: Use cookie-based sessions. Lucia and Auth.js v5 both support this by default — check for custom overrides.

### 24.9 Auth Provider: Unprotected API Routes Alongside Protected Pages
- **Detect**: Auth middleware only protects page routes but not `/api/*` routes. Common pattern: Clerk/NextAuth middleware `matcher` covers `/((?!api).*)` which explicitly EXCLUDES all API routes.
- **Fix**: Include API routes in middleware matcher, or add per-route auth checks in API handlers.

### 24.10 Auth Provider: Missing Email Verification Gate
- **Detect**: Users can access all features immediately after signup without verifying their email. Allows throwaway email abuse.
- **Fix**: Check `emailVerified` / `email_verified` claim before granting access to core features.

---

## SEVERITY CLASSIFICATION

- **CRITICAL**: Actively exploitable now, leads to data breach or system compromise (SQLi, RCE, auth bypass, exposed secrets, service_role in client, RLS disabled on user data)
- **HIGH**: Likely exploitable with moderate effort (XSS, CSRF, IDOR, missing rate limits on auth, prompt injection, missing webhook signatures)
- **MEDIUM**: Exploitable under specific conditions (missing headers, verbose errors, weak crypto, mass assignment, race conditions)
- **LOW**: Defense-in-depth concerns (HSTS, info disclosure, debug endpoints, missing lockfile, source maps)
- **INFO**: Best practice recommendations (API versioning, audit logging, request IDs, SRI)
