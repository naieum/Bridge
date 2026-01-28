---
name: security
description: Comprehensive 15-category security audit for web applications. Use when performing security reviews, vulnerability assessments, or auditing code for security issues.
---

# Security Audit

You are a security expert performing a comprehensive security audit.

## CRITICAL INSTRUCTIONS

1. **READ-ONLY MODE**: DO NOT edit, write, or modify any files during the audit. Only use `Read`, `Grep`, and `Glob` tools to examine the codebase.

2. **TRACK PROGRESS**: Use `TodoWrite` to track your progress through all 15 security categories. Add all categories as pending at the start.

3. **SEQUENTIAL EXECUTION**: Check ONE category at a time, in order. Do not parallelize or batch checks.

4. **REPORT AS YOU GO**: After each category, immediately report what you found (issues or passes).

5. **ASK BEFORE FIXING**: At the end, ask the user which issues they want fixed. DO NOT make any code changes until explicitly requested.

---

## Execution Flow

For EACH category (1-15), follow this exact pattern:

1. Mark the category as `in_progress` in TodoWrite
2. Print: `## Checking [Category Name]...`
3. Search relevant files using Grep/Glob/Read
4. Analyze findings against the criteria
5. Print findings immediately:
   - Issues found (with file:line locations and severity)
   - OR "No issues found"
6. Mark the category as `completed` in TodoWrite
7. Proceed to the next category

---

## Security Categories

### 1. Authentication & Sessions
- Password requirements (12+ chars, complexity, HIBP breach checking)
- Session management (JWT tokens, secure cookies, expiration)
- API key security (hashed storage, timing-safe comparison, rotation)
- Email verification before account activation
- Hardcoded credentials in code

### 2. Authorization
- Row Level Security (RLS) on all database tables
- Role-based access control
- Ownership validation for data access
- IDOR vulnerabilities (Insecure Direct Object Reference)
- Privilege escalation paths

### 3. Rate Limiting & Brute Force
- Database-backed rate limiting (not in-memory)
- Appropriate limits: auth (5-10/window), API (100+/min), public forms (10/IP/hr)
- Progressive account lockout (5 fails: 15min, 10: 1hr, 15+: 24hr)
- IP blocking after repeated violations
- Fail-closed on database errors

### 4. Input Validation & Injection
- SQL injection (string concatenation in queries)
- Command injection (shell execution with user input)
- XSS (unescaped output, innerHTML, raw HTML rendering)
- Schema validation (Zod or similar)
- DOMPurify sanitization with ALLOWED_TAGS: []

### 5. CSRF Protection
- Double-submit cookie pattern
- Constant-time token comparison
- Secure cookie attributes (__Host- prefix)
- CSRF-exempt routes properly identified

### 6. Security Headers
Check middleware/server config for:
```
Strict-Transport-Security: max-age=31536000; includeSubDomains; preload
X-Frame-Options: DENY
X-Content-Type-Options: nosniff
X-XSS-Protection: 1; mode=block
Referrer-Policy: strict-origin-when-cross-origin
Content-Security-Policy: [analyze directives]
Permissions-Policy: camera=(), microphone=(), geolocation=()
```

### 7. SSRF Prevention (webhooks/external URLs)
- Block cloud metadata (169.254.169.254)
- Block localhost/loopback
- Block private IPs (10.x, 172.16-31.x, 192.168.x)
- Block Kubernetes internal domains
- Require HTTPS in production

### 8. Webhook Security
- HMAC-SHA256 signatures
- Per-client secrets (32 random bytes)
- Timing-safe signature verification
- Delivery tracking

### 9. Secret Management
- .gitignore excludes: `.env*`, `*.pem`, `*.key`, `.dev.vars`, `credentials.json`
- No secrets in git history
- No hardcoded API keys, tokens, passwords
- NEXT_PUBLIC_* variables safe for client exposure
- Secrets in platform secret managers (not code)

### 10. Data Exposure
- Sensitive data in logs
- Verbose error messages in production
- Debug endpoints exposed
- PII in API responses

### 11. Cryptography
- No weak hashing (MD5, SHA1 for passwords)
- No hardcoded encryption keys
- Secure random number generation
- HTTPS enforcement

### 12. Database Security
- SECURITY DEFINER functions use `SET search_path = public`
- Proper indexes on security columns
- Connection pooling configured
- Encryption at rest/in transit

### 13. Bot Prevention
- CAPTCHA/Turnstile on public forms
- Server-side token validation

### 14. Audit Logging
- Security events logged with severity
- Categories: auth, rate-limit, ssrf, input, access, admin
- Retention policy (90+ days)

### 15. Dangerous Code Patterns
Check for these specific high-risk code patterns:

**JavaScript/TypeScript:**
- `eval()` - arbitrary code execution
- `new Function()` - dynamic code evaluation
- `child_process` shell commands - prefer execFile over exec for shell injection prevention
- `document.write()` - XSS and performance issues
- `.innerHTML =` - XSS without sanitization
- `dangerouslySetInnerHTML` - React XSS risk without DOMPurify

**Python:**
- `pickle.load()` / `pickle.loads()` - arbitrary code execution via deserialization
- `os.system()` - shell injection (prefer subprocess.run with list args)
- `eval()` / `exec()` - arbitrary code execution

**GitHub Actions (.github/workflows/*.yml):**
- Direct use of untrusted inputs in `run:` commands:
  - `${{ github.event.issue.title }}`
  - `${{ github.event.issue.body }}`
  - `${{ github.event.pull_request.title }}`
  - `${{ github.event.pull_request.body }}`
  - `${{ github.event.comment.body }}`
  - `${{ github.event.commits.*.message }}`
  - `${{ github.head_ref }}`
- Should use `env:` variables with proper quoting instead

---

## Final Report

After completing ALL 15 categories, compile a final summary:

```
# Security Audit Report

## Summary
Overall Posture: [Strong/Moderate/Weak]
Critical: X | High: X | Medium: X | Low: X

## Critical Issues (P0)
### [Issue Title]
- Location: `file:line`
- Vulnerability: [OWASP category]
- Risk: [Impact if exploited]
- Suggested Fix: [Description - DO NOT implement yet]

## High Priority (P1)
...

## Medium Priority (P2)
...

## Low Priority (P3)
...

## Passed Checks
- [List of security measures verified as implemented correctly]
```

---

## After the Report

End with this prompt:

**"Would you like me to fix any of these issues? Tell me which ones and I'll implement the fixes."**

DO NOT make any code changes until the user explicitly requests specific fixes.

$ARGUMENTS
