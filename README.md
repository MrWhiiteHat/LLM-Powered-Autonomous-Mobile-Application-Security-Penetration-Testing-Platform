# 🛡️ LLM-Powered Autonomous Mobile App Security Penetration Testing Platform

> **Mobile Security Agent** is an advanced, fully autonomous orchestration platform designed to streamline and automate mobile application penetration testing through a robust 10-phase security pipeline powered by a FastAPI backend and a database-less local hybrid RAG engine (TF-IDF + Okapi BM25) utilizing local LLMs.

![Version](https://img.shields.io/badge/version-2.0.0-blue.svg)
![Python](https://img.shields.io/badge/python-3.9%2B-brightgreen.svg)
![FastAPI](https://img.shields.io/badge/FastAPI-0.100%2B-009688.svg)

---

## 🏗️ Architecture Stack

The project operates entirely decoupled from managed databases or Docker runtimes, allowing for seamless deployment and isolated testing environments.

- **Frontend:** Vanilla JavaScript, HTML5, and CSS3 Dashboard interacting via asynchronous Fetch APIs.
- **API Engine:** FastAPI executing deep OS-level routines and managing asynchronous penetration testing workers.
- **RAG & Knowledge Base:** Local, database-less hybrid vector index (1,974 reference documents) mapping findings to OWASP, CWE, and CAPEC standards.
- **Local LLM Auditor:** Dynamic Zero-Day audit and cognitive false-positive suppression via local Qwen-3.5 4B model (via Ollama).
- **Deployment Mechanics:** Built-in `deploy.py` leverages Paramiko to transport, initialize, and daemonize (`systemd`) the application onto raw Ubuntu VPS infrastructure safely over SSH.

---

## 🔍 The 10-Phase Security Pipeline

When an APK/IPA is uploaded, it runs sequentially through:

1. **Reconnaissance:** Initial OSINT and metadata gathering.
2. **Static Code & Zero-Day Heuristic Analysis:** Extracting code logic, permissions, secrets, and executing taint-flow, reflection, and behavioral profiling audits.
3. **Reverse Engineering:** Inspecting configuration binaries, hidden URLs, and internal assets.
4. **Storage Security Assessment:** Mapping local file caching and DB flaws.
5. **Network Security:** TLS validations and cryptographic handshake flaws.
6. **API Security:** Inspecting REST/GraphQL endpoints discovered within the binary.
7. **Dynamic Runtime Analysis:** Memory validation, local instrumentation checks.
8. **RAG Vulnerability Mapping:** Querying the hybrid local index to enrich findings with CWE/CAPEC/OWASP data.
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
