# VibeGuard — Security Auditor for Vibe-Coded Projects

**170+ vulnerability checks · 24 categories · 3 commands · pre-commit secret blocking**

Built for projects that were vibe-coded with AI and shipped without a security review.

## Commands

| Command | What It Does | Auto-invoked? |
|---------|-------------|---------------|
| `/vibeguard:audit` | Scans project, produces a findings table | Yes — Claude runs it when you ask about security |
| `/vibeguard:fix` | Patches vulnerabilities from the audit | No — you must invoke manually |
| `/vibeguard:harden` | Adds security infrastructure proactively | No — you must invoke manually |

### Audit (the scanner)

```bash
/vibeguard:audit              # full project scan
/vibeguard:audit auth         # focus on authentication issues
/vibeguard:audit src/api/     # scan specific directory
/vibeguard:audit rls          # focus on Supabase RLS
/vibeguard:audit llm          # focus on LLM/AI security
```

Produces a severity-rated table. Never changes code.

### Fix (the patcher)

```bash
/vibeguard:fix all            # fix everything from the audit
/vibeguard:fix critical       # fix only CRITICAL severity
/vibeguard:fix critical high  # fix CRITICAL and HIGH
/vibeguard:fix 1,3,7          # fix specific findings by number
```

Shows before/after for every change. Asks for input when decisions are needed.

### Harden (proactive security)

```bash
/vibeguard:harden             # full hardening (shows plan first)
/vibeguard:harden headers     # add security headers only
/vibeguard:harden middleware  # add security middleware stack
/vibeguard:harden validation  # add input validation to endpoints
/vibeguard:harden env         # cleanup env vars, create .env.example
/vibeguard:harden logs        # strip/gate console.logs
```

Always shows a plan and asks for approval before making changes.

### Pre-Commit Hook

Automatically blocks `git commit` if staged files contain hardcoded secrets (API keys, private keys, connection strings, .env files). No action needed — it's active once the plugin is installed.

## What It Catches

| Category | Checks | Highlights |
|---|---|---|
| Injection Attacks | 9 | SQL, NoSQL, command, SSTI, GraphQL |
| XSS | 5 | Reflected, stored, DOM, React, SVG |
| Auth & Sessions | 9 | Hardcoded secrets, JWT misuse, broken reset |
| Authorization | 7 | IDOR, mass assignment, path traversal |
| Rate Limiting | 7 | Auth, API, uploads, pagination |
| CSRF | 2 | Missing tokens, token in GET |
| Security Headers | 9 | CSP, HSTS, CORS, all the headers |
| Data Exposure | 11 | Console.log leaks, env prefix leaks, EXIF |
| File Uploads | 3 | Type/size/origin issues |
| Dependencies | 4 | CVEs, wildcards, lockfile, SRI |
| Crypto | 5 | Math.random, timing attacks, weak algos |
| DoS | 4 | ReDoS, XML bombs, memory |
| WebSockets | 4 | Auth, origin, message injection |
| Deployment | 5 | Debug mode, defaults, Docker |
| API Security | 4 | Validation, batch abuse, exposed docs |
| Client-Side | 4 | Client-only auth, prototype pollution |
| Next.js/React | 9 | Server Actions, Route Handlers, App Router, SSR props |
| Database | 4 | Default creds, exposed ports |
| SSRF | 2 | URL fetching, DNS rebinding |
| Race Conditions | 3 | Double-spending, TOCTOU |
| Webhooks & Payments | 4 | Stripe signatures, price manipulation |
| Vibe-Coding Antipatterns | 8 | TODO auth, AI artifacts, mock code |
| **Auth Providers** | **10** | NextAuth/Auth.js, Clerk, Lucia misconfigs |
| **Supabase/BaaS** | **22** | RLS, service_role, storage, realtime |
| **LLM/AI** | **12** | Prompt injection, output safety, cost abuse |

## Install

```bash
# From a custom marketplace
/plugin marketplace add geraldang702/vibeguard
/plugin install vibeguard

# Or install directly from GitHub
/plugin install vibeguard --repo geraldang702/vibeguard
```

### Local Testing

```bash
git clone https://github.com/geraldang702/vibeguard.git
claude --plugin-dir ./vibeguard
```

## Design

The plugin enforces a strict **audit-first flow**:

1. **Scan** — `/vibeguard:audit` detects your stack, reads only the relevant reference files, scans everything
2. **Report** — Presents a findings table with severity, file, line number, and plain-English explanations
3. **Ask** — Stops and asks what you want to fix. Never auto-patches.
4. **Fix** — `/vibeguard:fix` only runs when you explicitly invoke it, shows before/after for every change
5. **Prevent** — The pre-commit hook blocks future secrets from being committed

The `fix` and `harden` skills have `disable-model-invocation: true` — Claude will never run them on its own, even if it thinks it should. You stay in control.

## Project Structure

```
vibeguard/
├── .claude-plugin/
│   ├── plugin.json              # plugin identity
│   └── marketplace.json         # marketplace catalog
├── skills/
│   ├── audit/                   # /vibeguard:audit (auto-invoked when relevant)
│   │   ├── SKILL.md
│   │   └── references/
│   │       ├── threat-matrix.md # 24 categories
│   │       ├── supabase-baas.md # 22 BaaS checks
│   │       └── llm-security.md  # 12 AI checks
│   ├── fix/                     # /vibeguard:fix (manual only)
│   │   └── SKILL.md
│   └── harden/                  # /vibeguard:harden (manual only)
│       └── SKILL.md
├── hooks/
│   └── hooks.json               # pre-commit secret blocker config
├── scripts/
│   └── secret-scanner.sh        # secret detection script
├── LICENSE
└── README.md
```

## Contributing

PRs welcome. To add a vulnerability check:

1. Add it to `skills/audit/references/threat-matrix.md` under the right category
2. Follow the format: `### N.N Name` → `Detect:` → `Fix:`
3. Add it to the scan priority list in `skills/audit/SKILL.md` if it's P0 or P1

## License

MIT
