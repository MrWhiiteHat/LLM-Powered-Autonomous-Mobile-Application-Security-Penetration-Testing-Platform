# 🤝 Contributing to Mobile Security Agent (MSA v2.0)

Thank you for your interest in contributing to **Mobile Security Agent (MSA v2.0)**! We welcome contributions from security researchers, reverse engineers, software developers, and documentation writers.

---

## 🧭 Code of Conduct & Ethics

All contributors are expected to uphold the highest ethical standards. Contributions that facilitate malicious exploitation, unconstrained cyberattacks, or illegal reverse-engineering bypasses will be rejected. All development is defensive and diagnostic.

---

## 🛠️ Local Development Setup

1. **Fork and Clone the Repository:**
   ```bash
   git clone https://github.com/<your-username>/LLM-Powered-Autonomous-Mobile-Application-Security-Penetration-Testing-Platform.git
   cd LLM-Powered-Autonomous-Mobile-Application-Security-Penetration-Testing-Platform
   ```

2. **Set Up Python Virtual Environment (Python 3.10+):**
   ```bash
   python -m venv venv
   # On Windows:
   venv\Scripts\activate
   # On Linux / macOS:
   source venv/bin/activate
   ```

3. **Install Dependencies:**
   ```bash
   pip install -r backend/requirements.txt
   ```

4. **Configure Environment:**
   ```bash
   cp .env.example .env
   ```

5. **Start Ollama & Local Model (Optional for full AI reasoning):**
   ```bash
   ollama pull qwen2.5-coder:1.5b
   ```

6. **Run the FastAPI Development Server:**
   ```bash
   cd backend
   python -m uvicorn main:app --reload --host 127.0.0.1 --port 8000
   ```

---

## 📐 Coding Standards & Guidelines

- **Python Style:** Follow [PEP 8](https://peps.python.org/pep-0008/) style standards. Type hints are strongly encouraged for public functions and classes.
- **Security-First Coding:**
  - Never interpolate unescaped user inputs directly into HTML templates (prevent XSS).
  - Use regex timeouts or safe patterns to avoid Regular Expression Denial of Service (ReDoS).
  - All network requests must specify an explicit timeout (`timeout=10`).
- **Module Architecture:**
  - Keep security modules modular inside `backend/modules/`.
  - Every analysis module must return standard dictionary outputs with a `findings` list.
- **Frontend Standards:**
  - Vanilla HTML5 / CSS3 / ES6+ JavaScript.
  - Zero heavy frontend framework dependencies to maintain high portability.

---

## 🧪 Testing & Verification

Before submitting a Pull Request:
1. Verify that the backend launches without syntax or import errors:
   ```bash
   python -c "import main; print('FastAPI app initialized successfully')"
   ```
2. Verify security data files parse cleanly:
   ```bash
   python -c "from knowledge.rag_engine import RAGEngine; r = RAGEngine(); print(f'Knowledge docs: {len(r.documents)}')"
   ```

---

## 🚀 Submitting Pull Requests

1. Create a descriptive feature branch:
   ```bash
   git checkout -b feature/dynamic-hook-enhancement
   ```
2. Commit your changes with meaningful conventional commit messages:
   ```bash
   git commit -m "feat(dynamic): add biometric authentication bypass inspection hook"
   ```
3. Push to your fork:
   ```bash
   git push origin feature/dynamic-hook-enhancement
   ```
4. Open a Pull Request against the `main` branch. Complete the PR template description.
