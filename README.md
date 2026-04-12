# 🛡️ LLM-Powered Autonomous Mobile App Security Penetration Testing Platform

> **Mobile Security Agent** is an advanced, fully autonomous orchestration platform designed to streamline and automate mobile application penetration testing through a robust 10-step security pipeline powered by a FastAPI backend and a local Vector Database (ChromaDB) for Retrieval-Augmented Generation (RAG).

![Version](https://img.shields.io/badge/version-2.0.0-blue.svg)
![Python](https://img.shields.io/badge/python-3.9%2B-brightgreen.svg)
![FastAPI](https://img.shields.io/badge/FastAPI-0.100%2B-009688.svg)

---

## 🏗️ Architecture Stack

The project operates entirely decoupled from managed databases or Docker runtimes, allowing for seamless deployment and isolated testing environments.

- **Frontend:** Vanilla JavaScript, HTML5, and CSS3 Dashboard interacting via asynchronous Fetch APIs.
- **API Engine:** FastAPI executing deep OS-level routines and managing asynchronous penetration testing workers.
- **RAG & Knowledge Base:** Local `ChromaDB` persisting OWASP mapping criteria (Mobile Top 10 & API Top 10). Dynamic vulnerability categorization.
- **Deployment Mechanics:** Built-in `deploy.py` leverages Paramiko to transport, initialize, and daemonize (`systemd`) the application onto raw Ubuntu VPS infrastructure safely over SSH.

---

## 🔍 The 10-Step Security Pipeline

When an APK/IPA is uploaded, it runs sequentially through:

1. **Reconnaissance:** Initial OSINT and metadata gathering.
2. **Static Code Analysis:** Extracting code logic, permissions, and hardcoded secrets.
3. **Reverse Engineering:** Inspecting configuration binaries, hidden URLs, and internal assets.
4. **Storage Security Assessment:** Mapping local file caching and DB flaws.
5. **Network Security:** TLS validations and cryptographic handshake flaws.
6. **API Security:** Inspecting REST/GraphQL endpoints discovered within the binary.
7. **Dynamic Runtime Analysis:** Memory validation, local instrumentation checks.
8. **Vulnerability Mapping:** Aggregating identified indicators mapping to OWASP.
9. **Risk Assessment:** Contextualizing scores using CVSS schemas.
10. **Report Generation:** Exporting `JSON` and `HTML` deliverables automatically.

---

## 🚀 Installation & Local Usage

1. **Clone the repo**
   ```bash
   git clone git@github.com:MrWhiiteHat/LLM-Powered-Autonomous-Mobile-Application-Security-Penetration-Testing-Platform.git
   cd LLM-Powered-Autonomous-Mobile-Application-Security-Penetration-Testing-Platform
   ```

2. **Initialize Environment**
   ```bash
   python -m venv venv
   source venv/bin/activate  # On Windows: venv\Scripts\activate
   pip install -r backend/requirements.txt
   ```

3. **Start the Agent**
   ```bash
   cd backend
   python main.py
   ```
   *Dashboard available locally at `http://localhost:8000`*

---

## 🌐 Remote VPS Deployment

The tool comes with an automated `deploy.py` configuration designed to drop the payload securely onto an Ubuntu server.

1. Configure `VPS_HOST`, `VPS_USER`, and `VPS_PASS` in `deploy.py`.
2. Execute the transporter:
   ```bash
   python deploy.py
   ```
This will automatically build the environment, establish a `systemd` daemon, and attach ufw rules.

---

## 📄 License and Disclaimer

This software is for **educational and authorized penetration testing purposes only**. The developers assume no liability for misuse or damage caused by this agent. Use responsibly.
