# Supabase & BaaS Security Reference

> Critical security checks for Supabase, Firebase, and Backend-as-a-Service projects.
> These are the #1 source of critical vulnerabilities in vibe-coded projects.

---

## WHY THIS MATTERS

BaaS platforms give you a database and auth out of the box, but security is NOT automatic. The most dangerous misconception in vibe-coding is: "I'm using Supabase/Firebase, so my data is secure." It's not. The database is directly accessible from the browser, and the ONLY thing standing between an attacker and your data is your Row Level Security (RLS) policies or Firestore rules.

---

## SUPABASE SECURITY

### S1: RLS Not Enabled on Tables

**The single most critical Supabase vulnerability.** If RLS is not enabled on a table, ANY authenticated user (or even anonymous users if anon access is on) can read, write, and delete ALL rows.

- **Detect**: Check `supabase/migrations/` for `ALTER TABLE ... ENABLE ROW LEVEL SECURITY`. Check if any table is created WITHOUT enabling RLS. Check the Supabase dashboard or query `pg_tables` for tables with `rowsecurity = false`.
- **Fix**: Enable RLS on EVERY table that contains user data: `ALTER TABLE tablename ENABLE ROW LEVEL SECURITY;`

### S2: Overly Permissive RLS Policies

RLS is enabled but the policies are too broad.

- **Detect**: Look for policies with:
  - `USING (true)` — allows ALL users to read ALL rows
  - `WITH CHECK (true)` — allows ALL users to insert/update ANY row
  - `FOR ALL` with no meaningful condition
  - Missing ownership check (`auth.uid() = user_id`)
  - Policies that check role from a user-editable field instead of `auth.jwt()`
- **Fix**: Every policy should scope to the authenticated user:
  ```sql
  CREATE POLICY "Users can only see own data"
    ON profiles FOR SELECT
    USING (auth.uid() = user_id);
  ```

### S3: Service Role Key in Client-Side Code

The `service_role` key bypasses ALL RLS policies. If it's in client code, anyone can extract it and have full database access.

- **Detect**: Search client-side code for:
  - `SUPABASE_SERVICE_ROLE_KEY`, `SERVICE_ROLE_KEY`, `supabase_service_key`
  - `NEXT_PUBLIC_SUPABASE_SERVICE_ROLE` or any `NEXT_PUBLIC_`/`VITE_`/`REACT_APP_` prefixed service role var
  - `createClient(url, serviceRoleKey)` in browser-executed code
  - The actual key value (starts with `eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9` with `"role":"service_role"` when decoded)
- **Fix**: Service role key must ONLY be used server-side (API routes, Edge Functions, server actions). Client code should ONLY use the `anon` key.

### S4: Anon Key Abuse

The `anon` key is public by design, but without proper RLS it's a skeleton key.

- **Detect**: Check what operations are possible with just the anon key. If RLS is off or permissive, anon users can read/write everything.
- **Fix**: RLS must be the security boundary. The anon key is fine to expose IF RLS is properly configured.

### S5: Storage Bucket Policies

Supabase Storage has its own access policies separate from database RLS.

- **Detect**:
  - Buckets set to `public` that contain private user files
  - Missing storage policies (default = deny, but misconfiguration is common)
  - Policies that allow any authenticated user to read all files (not scoped to owner)
  - No file size limits on uploads
  - No file type restrictions
- **Fix**:
  - Private buckets for user files
  - Scope policies: `(bucket_id = 'avatars' AND auth.uid()::text = (storage.foldername(name))[1])`
  - Add file size limits in storage policies
  - Validate file types

### S6: Realtime Subscriptions Leaking Data

Supabase Realtime lets clients subscribe to database changes. Without RLS, users can subscribe to ALL changes on a table.

- **Detect**: Check if Realtime is enabled on tables with sensitive data. Check if RLS policies cover SELECT (Realtime uses SELECT policies).
- **Fix**: RLS SELECT policies must be properly scoped. Disable Realtime on tables that don't need it.

### S7: Edge Functions Without Auth

Supabase Edge Functions (Deno) may not check authentication.

- **Detect**: Check Edge Functions for `Authorization` header validation, `supabase.auth.getUser()` calls
- **Fix**: Verify JWT at the start of every Edge Function:
  ```typescript
  const { data: { user }, error } = await supabase.auth.getUser(
    req.headers.get('Authorization')?.replace('Bearer ', '')
  );
  if (!user) return new Response('Unauthorized', { status: 401 });
  ```

### S8: Database Functions (RPC) Without Security

`supabase.rpc('function_name')` calls PostgreSQL functions. If the function is `SECURITY DEFINER`, it runs with the function owner's privileges (usually superuser), bypassing RLS.

- **Detect**: Check for `SECURITY DEFINER` functions that accept user input without validation, or that access data without checking `auth.uid()`
- **Fix**: Use `SECURITY INVOKER` (default) unless absolutely needed. If `SECURITY DEFINER` is required, validate all inputs and explicitly check `auth.uid()` within the function.

### S9: Auth Configuration Issues

- **Detect**:
  - Email confirmations disabled (users can sign up with any email)
  - No rate limiting on auth endpoints
  - Password requirements not configured
  - OAuth providers configured with overly broad scopes
  - Missing email domain restrictions (if app is for specific org)
  - JWT expiry too long (default is 1 hour, some set to days/weeks)
- **Fix**: Enable email confirmation, configure password strength, restrict OAuth scopes, set reasonable JWT expiry

### S10: Missing RLS on Junction/Linking Tables

Many-to-many relationship tables (e.g., `team_members`, `project_users`) often lack RLS even when the main tables have it.

- **Detect**: Identify junction tables and check for RLS
- **Fix**: Add RLS policies that verify the authenticated user has access to at least one side of the relationship

### S11: Supabase Migrations Contain Secrets

- **Detect**: Migration files with hardcoded passwords, API keys, or service role keys
- **Fix**: Use migration variables, environment-specific seeds

---

## FIREBASE SECURITY

### F1: Firestore Rules Too Permissive

- **Detect**: `firestore.rules` with:
  - `allow read, write: if true;`
  - `allow read, write: if request.auth != null;` (any logged-in user can read/write everything)
  - Missing rules (Firestore denies by default, but test mode sets everything to `true`)
  - Rules that expired (test mode sets a date-based allow-all)
- **Fix**: Scope every rule to document ownership:
  ```
  match /users/{userId} {
    allow read, write: if request.auth.uid == userId;
  }
  ```

### F2: Firebase Admin SDK in Client

- **Detect**: `firebase-admin` imported in client-side code, or admin credentials (service account JSON) in browser bundle
- **Fix**: Admin SDK server-side only. Use client SDK with Firestore Rules as security boundary.

### F3: Realtime Database Rules

- **Detect**: `.read: true` or `.write: true` at root level in `database.rules.json`
- **Fix**: Scope rules to authenticated user paths

### F4: Storage Rules
- **Detect**: `allow read, write: if true;` in storage rules
- **Fix**: Scope to user paths, validate file types/sizes in rules

### F5: Firebase Config Exposure
- **Detect**: Firebase config (apiKey, projectId, etc.) treated as secret — it's actually meant to be public, but must be paired with proper Firestore/Storage rules
- **Fix**: Firebase config is safe to expose IF rules are properly configured. The security boundary is rules, not config secrecy.

---

## GENERAL BAAS PATTERNS

### B1: Client-Side Data Filtering
- **Detect**: Fetching ALL records from BaaS and filtering client-side (`supabase.from('posts').select('*')` then `.filter()` in JS). The user sees filtered results, but ALL data was sent over the network.
- **Fix**: Filter server-side with proper queries and RLS

### B2: Trusting Client-Side Role Checks
- **Detect**: UI hides admin features based on `user.role`, but no server-side enforcement. User can call admin APIs directly.
- **Fix**: Enforce roles in RLS policies or server-side middleware, not just UI

### B3: Missing Cascading Deletes / Orphaned Data
- **Detect**: When a user account is deleted, their data remains accessible or orphaned
- **Fix**: Set up cascading deletes or cleanup triggers

### B4: Exposed Database URL
- **Detect**: Direct PostgreSQL connection string (`postgresql://...`) in client code or public env vars
- **Fix**: Direct DB connections should only be used server-side. Clients use the Supabase client library with anon key.
