# 🛡️ Security Policy

## 📋 Scope & Ethical Usage Notice

**Mobile Security Agent (MSA v2.0)** is an autonomous security auditing and penetration testing platform engineered strictly for:
- Authorized security assessments of applications you own or have explicit written permission to test.
- Defensive application hardening, DevSecOps pipeline integration, and academic research.

> [!CAUTION]
> Scanning third-party applications without prior written consent from the copyright holder or application operator is illegal under computer misuse and cybersecurity laws in most jurisdictions. The maintainers and contributors assume no liability for unauthorized or malicious use.

---

## 🔒 Supported Versions

Only the latest release branch of MSA is actively maintained and receives security updates:

| Version | Supported          | Status             |
| ------- | ------------------ | ------------------ |
| 2.0.x   | :white_check_mark: | Current Active     |
| < 2.0   | :x:                | Deprecated         |

---

## 🚨 Reporting a Vulnerability

If you discover a security vulnerability, privilege escalation flaw, or potential code execution vulnerability within the platform itself:

1. **Do NOT open a public GitHub issue.** Public issues disclose vulnerabilities to malicious actors before maintainers can deliver a patch.
2. **Submit via GitHub Private Vulnerability Reporting:**
   - Navigate to the repository's **Security** tab.
   - Click **Report a vulnerability** to open a confidential advisory draft.
3. **Include the following details:**
   - Affected module or endpoint (e.g., `backend/modules/api_testing.py`).
   - Detailed proof of concept (PoC) or reproduction steps.
   - Estimated impact and CVSS assessment.
   - Proposed remediation patch or diff if available.

### Response Timeline
- **Initial Acknowledgement:** Within 48 hours.
- **Triage & Validation:** Within 5 business days.
- **Fix & Public Advisory:** Coordinated release with reporter attribution.
