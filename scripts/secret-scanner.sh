#!/bin/bash
# VibeGuard pre-commit secret scanner
# Blocks git commits (via Claude Code) that contain hardcoded secrets.
#
# Claude Code PreToolUse hook. Receives JSON on stdin describing the
# tool being used. Exits with code 2 to block, 0 to allow.

# Check for jq — skip silently if not installed
if ! command -v jq &>/dev/null; then
  exit 0
fi

# Read hook input
INPUT=$(cat)

# Only run on Bash tool
TOOL_NAME=$(echo "$INPUT" | jq -r '.tool_name // empty' 2>/dev/null) || exit 0
if [ "$TOOL_NAME" != "Bash" ]; then
  exit 0
fi

# Only check git commit commands
COMMAND=$(echo "$INPUT" | jq -r '.tool_input.command // empty' 2>/dev/null) || exit 0
if ! echo "$COMMAND" | grep -qE '^\s*git\s+commit'; then
  exit 0
fi

# Temp file for findings (avoids subshell variable scoping issues)
REPORT_FILE=$(mktemp 2>/dev/null || echo "/tmp/vibeguard-$$")
: > "$REPORT_FILE"

# Get staged files using null delimiter (handles spaces in filenames)
git diff --cached --name-only -z --diff-filter=ACM 2>/dev/null | while IFS= read -r -d '' FILE; do
  # Skip binary files and lockfiles
  case "$FILE" in
    *.lock|package-lock.json|yarn.lock|pnpm-lock.yaml|*.min.js|*.min.css)
      continue
      ;;
  esac
  if file "$FILE" 2>/dev/null | grep -q "binary"; then
    continue
  fi

  # .env files should never be committed
  case "$FILE" in
    .env|.env.local|.env.production|.env.development|.env.staging)
      echo "  ⛔ $FILE: Environment file should not be committed" >> "$REPORT_FILE"
      continue
      ;;
  esac

  # Get staged content
  CONTENT=$(git show ":$FILE" 2>/dev/null || true)
  [ -z "$CONTENT" ] && continue

  # AWS Access Keys
  if echo "$CONTENT" | grep -qE 'AKIA[0-9A-Z]{16}'; then
    echo "  ⛔ $FILE: AWS Access Key (AKIA...)" >> "$REPORT_FILE"
  fi

  # Anthropic keys
  if echo "$CONTENT" | grep -qE 'sk-ant-[a-zA-Z0-9_-]{20,}'; then
    echo "  ⛔ $FILE: Anthropic API key (sk-ant-...)" >> "$REPORT_FILE"
  fi

  # OpenAI keys (classic sk-XXXX and modern sk-proj-XXXX formats)
  if echo "$CONTENT" | grep -qE 'sk-proj-[a-zA-Z0-9_-]{20,}'; then
    echo "  ⛔ $FILE: OpenAI API key (sk-proj-...)" >> "$REPORT_FILE"
  elif echo "$CONTENT" | grep -qE 'sk-[a-zA-Z0-9]{20,}' && ! echo "$CONTENT" | grep -qE 'sk-ant-'; then
    echo "  ⛔ $FILE: OpenAI API key (sk-...)" >> "$REPORT_FILE"
  fi

  # GitHub tokens
  if echo "$CONTENT" | grep -qE 'gh[pousr]_[a-zA-Z0-9]{36,}'; then
    echo "  ⛔ $FILE: GitHub token" >> "$REPORT_FILE"
  fi

  # Stripe keys
  if echo "$CONTENT" | grep -qE '[sr]k_(live|test)_[a-zA-Z0-9]{20,}'; then
    echo "  ⛔ $FILE: Stripe API key" >> "$REPORT_FILE"
  fi

  # Supabase service role (variable name + JWT value)
  if echo "$CONTENT" | grep -qiE 'SERVICE_ROLE'; then
    if echo "$CONTENT" | grep -qE 'SERVICE_ROLE.{0,30}ey[a-zA-Z0-9]'; then
      echo "  ⛔ $FILE: Supabase service_role key (bypasses ALL RLS)" >> "$REPORT_FILE"
    fi
  fi

  # Private keys (PEM)
  if echo "$CONTENT" | grep -qE 'BEGIN (RSA |EC |DSA |OPENSSH )?PRIVATE KEY'; then
    echo "  ⛔ $FILE: Private key" >> "$REPORT_FILE"
  fi

  # Database connection strings with credentials
  if echo "$CONTENT" | grep -qE '(mongodb(\+srv)?|postgres(ql)?|mysql|redis|amqp)://[^:]+:[^@]+@'; then
    echo "  ⛔ $FILE: Database connection string with credentials" >> "$REPORT_FILE"
  fi

  # Slack tokens
  if echo "$CONTENT" | grep -qE 'xox[baprs]-[a-zA-Z0-9-]{10,}'; then
    echo "  ⛔ $FILE: Slack token" >> "$REPORT_FILE"
  fi

  # SendGrid keys
  if echo "$CONTENT" | grep -qE 'SG\.[a-zA-Z0-9_-]{22,}'; then
    echo "  ⛔ $FILE: SendGrid API key" >> "$REPORT_FILE"
  fi

  # Clerk secret key in client code
  if echo "$CONTENT" | grep -qiE 'NEXT_PUBLIC.*CLERK.*SECRET'; then
    echo "  ⛔ $FILE: Clerk secret key exposed as NEXT_PUBLIC (use CLERK_SECRET_KEY server-side only)" >> "$REPORT_FILE"
  fi

  # NextAuth secret that looks weak
  if echo "$CONTENT" | grep -qiE 'NEXTAUTH_SECRET\s*=\s*["'"'"'](password|secret|changeme|test|dev)'; then
    echo "  ⛔ $FILE: Weak NEXTAUTH_SECRET value" >> "$REPORT_FILE"
  fi
done

# Check if any secrets were found
if [ -s "$REPORT_FILE" ]; then
  echo "VibeGuard: Blocked commit — secrets detected in staged files:"
  cat "$REPORT_FILE"
  echo ""
  echo "Move secrets to environment variables and add .env to .gitignore."
  rm -f "$REPORT_FILE"
  exit 2
fi

rm -f "$REPORT_FILE"
exit 0
