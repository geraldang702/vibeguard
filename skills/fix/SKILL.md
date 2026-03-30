---
name: fix
description: "Fix security vulnerabilities found by /vibeguard:audit. Must be invoked manually — will never run automatically. Accepts arguments: 'all', 'critical', 'critical high', or specific issue numbers like '1,3,7'. Always run /vibeguard:audit first."
argument-hint: "[all|critical|critical high|1,3,7]"
disable-model-invocation: true
---

# VibeGuard Security Fix

Apply fixes for vulnerabilities found by the audit. This skill modifies code, so it requires explicit user invocation.

## What to Fix

Parse "$ARGUMENTS" to determine scope:

- `all` → fix every finding from the most recent audit
- `critical` → fix only CRITICAL severity
- `critical high` → fix CRITICAL and HIGH severity
- `1,3,7` (numbers) → fix only those specific findings by their # from the audit table
- Empty → ask the user what they want to fix. Do not guess.

If no audit has been run in this conversation yet, tell the user:
> "No audit findings in this conversation. Run `/vibeguard:audit` first, then come back with `/vibeguard:fix`."

If an audit WAS run earlier in this conversation, refer back to the findings table from that audit. Use the same issue numbers, severities, and file paths from that table.

## How to Fix

For each approved finding:

### 1. Show the vulnerable code (2-3 lines of context)

```
// File: src/lib/supabase.ts:14
const supabase = createClient(url, 'eyJhbGci...')  // ← service_role key
```

### 2. Apply the fix with a comment

```typescript
// SECURITY FIX (vibeguard #1): Moved service_role to server-side only. Client uses anon key.
const supabase = createClient(url, process.env.NEXT_PUBLIC_SUPABASE_ANON_KEY!)
```

### 3. Show what changed

Briefly state what was done and why, in plain English.

## Decisions That Need User Input

Some fixes require choices. Don't guess — ask with sensible defaults:

- **Rate limit numbers**: "How many login attempts per 15 minutes? (default: 5)"
- **CORS origins**: "Which domains should be allowed? (default: your production domain only)"
- **Auth strategy**: "Are you using session cookies, JWTs, or Supabase Auth?"
- **File upload limits**: "Max file size for uploads? (default: 10MB)"
- **Password policy**: "Minimum password length? (default: 8 characters)"

## After All Fixes

Present a changelog:

```
## VibeGuard Fix Summary

| # | Issue Fixed | File | What Changed |
|---|------------|------|-------------|
| 1 | service_role in client | src/lib/supabase.ts | Replaced with anon key, moved service_role to server |
| 3 | Hardcoded API key | src/utils/ai.ts | Replaced with process.env.OPENAI_API_KEY |

**New dependencies needed**: `npm install express-rate-limit helmet`
**New env vars needed**: Add to .env → OPENAI_API_KEY, SUPABASE_SERVICE_ROLE_KEY
**Files modified**: 4
**Files created**: 1 (.env.example)
```

## Reference

If you need detailed fix patterns for a specific vulnerability type, invoke the audit skill's reference files. The threat-matrix has a "Fix" line under each check with the exact remediation. Only read the specific section you need — use the TABLE OF CONTENTS to jump there.
