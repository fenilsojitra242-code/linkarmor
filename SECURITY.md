# Security Policy & Responsible Disclosure

## Supported Versions

LinkArmor releases are evaluated against adversarial URL obfuscation techniques, zero-day evasion tactics, and security vulnerabilities.

| Version | Supported          | Security Maintenance Status |
| ------- | ------------------ | --------------------------- |
| 1.2.x   | :white_check_mark: | Active Current Release      |
| 1.1.x   | :white_check_mark: | Security Patches Only       |
| < 1.0   | :x:                | Deprecated                  |

## Reporting a Vulnerability

The LinkArmor engineering team takes system integrity, adversarial model evasion, and application security seriously.

If you uncover a security vulnerability, model bypass attack vector, or sensitive information leak within LinkArmor:

1. **Do not disclose the vulnerability publicly** in GitHub Issues or public discussions.
2. Send an email with a reproducible proof of concept (PoC) directly to:
   - **Lead Engineer:** Fenil Sojitra (`fenilsojitra242@gmail.com`)
3. Include:
   - Type of vulnerability (e.g., SSRF, URL parser desync, bypass heuristic, injection).
   - Sample malicious payload / URL triggering the vulnerability.
   - Environment and deployment configuration where reproduced.

### Response Timelines & SLAs
- **Acknowledgment:** Within 24-48 hours of initial report.
- **Triage & Reproduction:** Within 72 hours.
- **Patch Release & Security Advisory:** Within 7 to 14 business days depending on vulnerability severity.
