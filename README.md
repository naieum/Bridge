# Bridge - Security Audit Plugin for Claude Code

A Claude Code plugin that runs comprehensive security audits on your codebase. Just type `/security` and it'll check your app against 15 security categories.

## What it checks

- Authentication & session management
- Authorization & access control
- Rate limiting
- SQL/XSS/command injection
- CSRF & SSRF
- Security headers
- Secrets in code
- Cryptography issues
- Database security
- Dangerous code patterns (eval, innerHTML, etc.)
- And more...

## Installation

### From GitHub (private repo)

```bash
claude plugins add naieum/Bridge
```

### From local directory

If you've cloned the repo:

```bash
claude plugins add /path/to/Bridge
```

## Usage

Once installed, just run:

```
/security
```

Claude will scan your codebase category by category and report any issues it finds. It won't make changes without asking first.

## How it works

The plugin adds a `/security` skill that tells Claude how to systematically audit your code. It uses read-only tools (Grep, Glob, Read) to examine your files and reports findings as it goes.

Each category gets checked one at a time with a summary of what was found. At the end, you get the full picture and can decide what to fix.

## License

MIT
