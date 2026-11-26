# GOTU — Advanced OSINT & Deep Intelligence Investigation Platform

> **For authorised use only.** GOTU is designed for legitimate OSINT investigations using publicly available information and authorised datasets. Never use GOTU to investigate people without lawful authority. Always comply with applicable law and your organisation's policies.

---

## Overview

GOTU is a modular, recursive, multi-source OSINT intelligence platform. It analyses an initial indicator (username, email, domain, organisation, etc.), runs relevant intelligence engines in parallel, discovers new leads, investigates them recursively within configurable limits, and produces evidence-based findings with full source provenance.

## Architecture

```
gotu/
├── backend/           # Fastify 5 API server (Node.js ESM)
│   └── src/
│       ├── engines/   # Intelligence engine adapters
│       ├── orchestrator/  # Recursive investigation engine
│       ├── jobs/      # SQLite-backed job queue
│       ├── audit/     # HMAC + hash-chain audit log
│       ├── auth/      # Argon2id + TOTP MFA
│       ├── routes/    # API route handlers
│       └── config/    # DB, crypto, env config
├── frontend/          # React 19 + Vite + Tailwind dark UI
├── data/              # SQLite database + salt files (gitignored)
├── .env.example       # Required environment variables
└── start.sh           # Production startup script
```

## Quick Start

### Prerequisites
- Node.js 20+
- npm 10+

### Setup

```bash
# 1. Clone and enter project
cd /path/to/gotu

# 2. Install backend dependencies
cd backend && npm install && cd ..

# 3. Install and build frontend
cd frontend && npm install && npm run build && cd ..

# 4. Configure environment
cp .env.example .env
# Edit .env — set GOTU_ENCRYPTION_KEY, GOTU_AUDIT_HMAC_KEY, GOTU_SESSION_SECRET

# 5. Generate secure keys
node -e "console.log('GOTU_ENCRYPTION_KEY=' + require('crypto').randomBytes(32).toString('hex'))"
node -e "console.log('GOTU_AUDIT_HMAC_KEY=' + require('crypto').randomBytes(32).toString('hex'))"

# 6. Start the platform
bash start.sh
# Or: cd backend && node src/server.js
```

Open **http://localhost:4000** in your browser.

## Intelligence Engines

| Engine | Input Types | API Key Required | Notes |
|--------|------------|-----------------|-------|
| **Username** | username | Optional (GitHub token) | GitHub, Reddit, HackerNews, GitLab, Keybase, npm. Instagram/TikTok/Facebook/LinkedIn: unsupported (no reliable free API) |
| **Domain** | domain, url | None | RDAP/WHOIS, DNS (A/AAAA/MX/TXT/NS/SOA), Certificate Transparency (crt.sh) |
| **Email** | email | Optional (HIBP) | RFC 5322 validation, MX lookup, disposable detection, breach check |
| **Search** | most types | Optional (Google CSE, Brave) | Dork query builder (always free), CommonCrawl CDX, Google CSE, Brave Search |
| **Legal** | name, organization | Optional (CourtListener key) | CourtListener (US federal), OFAC SDN sanctions. All results carry mandatory disclaimer. |
| **Business** | organization, name, domain | Optional (OpenCorporates) | OpenCorporates (140+ jurisdictions), SEC EDGAR |
| **Financial** | organization, other (blockchain) | None | SEC EDGAR filings, public Bitcoin/Ethereum address lookup. Never accesses private accounts. |

## Security Architecture

- **Argon2id** password hashing (memory: 64 MiB, iterations: 3)
- **TOTP MFA** via speakeasy (optional or required, configurable)
- **AES-256-GCM** column-level encryption for all sensitive DB fields
- **HMAC-SHA256 + hash chain** tamper-evident audit log
- **Full SSRF protection**: IPv4 (RFC1918 + all special ranges), IPv6 (loopback, ULA, link-local, multicast, 6to4, IPv4-mapped), cloud metadata endpoints, DNS rebinding, redirect chain validation
- **CSRF protection** on all mutations (`@fastify/csrf-protection`)
- **Security headers** (`@fastify/helmet`): CSP, HSTS, X-Frame-Options, noSniff, Referrer-Policy
- **Rate limiting** per-IP global + per-route limits
- **Session security**: HttpOnly + Secure + SameSite=Strict cookies, session rotation on login
- **API keys** stored encrypted in DB, never transmitted to frontend
- **Account lockout** after 10 failed login attempts (15-minute lockout)
- **Data isolation**: every investigation and finding scoped to its owner; 403 on cross-user access

## Running Tests

```bash
cd backend
npm test
# 120 tests: unit (crypto, SSRF, job queue, engines) + integration (auth, session, audit, investigations)
```

## Audit Log Verification

```bash
cd backend
node src/audit/verify.js
# Checks HMAC integrity and hash chain continuity of all audit records
# Detects modification, deletion, and reordering
```

## Ethical and Legal Constraints (Enforced)

- **No facial recognition**: Image engine explicitly excludes face-matching APIs
- **No credential testing**: Email engine never probes authentication endpoints; Pwned Passwords NOT used
- **No private data access**: Financial engine restricted to public filings and public blockchain only
- **SSRF protection**: All outbound requests validated against comprehensive IP blocklist
- **Legal disclaimers**: Every legal finding carries a mandatory disclaimer distinguishing allegations from convictions
- **Source provenance**: Every finding stores its source URL and timestamp
- **Confidence labelling**: Findings labelled confirmed/probable/possible/unverified — not as statistical probabilities
- **Identity caution**: Name matches alone are `unverified`; two independent sources required for `possible`

## Known Limitations

- Database is not full-disk encrypted (SQLCipher not available on this environment without root). All sensitive columns are AES-256-GCM encrypted at the application layer.
- Instagram, TikTok, Facebook, LinkedIn username checks are unsupported — no reliable public API exists.
- Twitter/X profile lookup requires paid API key ($100/mo Basic tier).
- Google CSE searches a custom engine index, not full Google Search.
- DuckDuckGo Instant Answers API does NOT provide web search results and is NOT used.
- CommonCrawl CDX provides URL presence data only, not keyword search.

## License

For authorised investigative and educational use only.
