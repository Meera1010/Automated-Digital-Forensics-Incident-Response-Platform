# Security Policy

## Supported Versions

| Version | Supported          |
|---------|--------------------|
| 1.0.x   | :white_check_mark: |
| < 1.0   | :x:                |

## Reporting a Vulnerability

We take the security of the ADFIR Platform seriously. If you discover a security vulnerability, please report it responsibly.

### How to Report

1. **Do NOT** open a public GitHub issue for security vulnerabilities.
2. **Email** the maintainers with a detailed description of the vulnerability.
3. Include the following information:
   - Type of vulnerability (e.g., SQLi, XSS, IDOR, authentication bypass)
   - Steps to reproduce the issue
   - Potential impact assessment
   - Suggested fix (if any)

### What to Expect

- **Acknowledgement**: Within 48 hours of your report
- **Status Update**: Within 7 days with an assessment and timeline
- **Resolution**: Security patches are prioritised and released as soon as possible

### Scope

The following are in scope for security reports:

- Authentication and authorisation bypasses
- SQL injection or ORM query manipulation
- Cross-site scripting (XSS) in the frontend
- Evidence vault encryption weaknesses
- Audit chain integrity violations
- Sensitive data exposure (secrets, PII leaks)
- Insecure direct object references (IDOR)

### Out of Scope

- Vulnerabilities in third-party dependencies (report these upstream)
- Denial of service attacks against the lab environment
- Social engineering attacks
- Issues that require physical access to the server

## Security Best Practices

This project follows these security practices:

- **No hardcoded secrets** — all sensitive values loaded from environment variables
- **Parameterised queries** — all SQL via SQLAlchemy ORM (no raw SQL)
- **Input validation** — Marshmallow schemas on every API endpoint
- **AES-256-GCM encryption** — for evidence storage with per-artifact nonces
- **SHA-256 integrity hashing** — blockchain-inspired audit chain
- **JWT authentication** — with role-based access control (RBAC)
- **Immutable audit log** — DB user has no DELETE/UPDATE rights on audit tables

## Acknowledgements

We appreciate the security research community's efforts to responsibly disclose vulnerabilities. Contributors who report valid issues will be acknowledged in release notes (with permission).
