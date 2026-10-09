# MSA v2.0 — Benchmark & Evaluation Reproducibility Guide

## Environment Specification

| Component | Version / Value |
| :--- | :--- |
| **Operating System** | Windows 11 Pro 24H2 (Build 26100) |
| **Python** | 3.14.0 (CPython) |
| **Java/JDK** | OpenJDK 17 (for JADX decompilation) |
| **Android SDK** | Platform-tools 35.0.2 |
| **ADB** | 1.0.41 |
| **JADX** | 1.5.1 |
| **Androguard** | 3.3.5 |
| **Frida** | 17.15.3 (frida-tools 13.9.0) |
| **Ollama** | 0.9.x (Windows service) |
| **LLM Model** | qwen2.5-coder:1.5b (986 MB, CPU-only, num_gpu=0) |
| **MSA Version** | 2.0.0 |
| **FastAPI** | 0.109.0 |
| **Uvicorn** | 0.27.0 |
| **Hardware** | Intel Core i7-12700H (14C/20T), 16 GB DDR5, NVMe SSD |
| **RAM Available** | ~12 GB (after OS overhead) |
| **GPU** | Intel Iris Xe (integrated, not used for LLM inference) |

## Benchmark Framework Versions

| Benchmark Suite | Version | Source |
| :--- | :--- | :--- |
| DroidBench | 3.0 | https://github.com/secure-software-engineering/DroidBench |
| Ghera | 1.0 | https://bitbucket.org/secure-it-i/android-app-vulnerability-benchmarks |
| OWASP MASVS | 2.1.0 | https://github.com/OWASP/owasp-masvs |
| OWASP MASTG | Latest | https://github.com/OWASP/owasp-mastg |
| DIVA | 1.0 | https://github.com/payatu/diva-android |
| AndroGoat | 1.0 | https://github.com/satishpatnayak/AndroGoat |
| InsecureBankv2 | 2.0 | https://github.com/dineshshetty/Android-InsecureBankv2 |
| OVAA | 1.0 | https://github.com/AjeeDevApps/ovaa |
| MobSF (comparison) | 4.4.0 | https://github.com/MobSF/Mobile-Security-Framework-MobSF |

## Dataset Acquisition

### DroidBench APKs
```bash
git clone https://github.com/secure-software-engineering/DroidBench.git
# APKs are pre-compiled in apk/ directory
```

### Vulnerable Applications
Download from respective GitHub releases pages. Place APKs in:
```
benchmark/datasets/
```

### Real-World Applications
Applications were legally obtained from Google Play Store for offline security research analysis.
No credentials were extracted, no live APIs attacked, no dynamic testing was performed on production services.

## Running the Benchmark

### Prerequisites
```powershell
# 1. Activate virtual environment
.\venv\Scripts\Activate.ps1

# 2. Ensure Ollama is running with qwen2.5-coder:1.5b
ollama serve
ollama pull qwen2.5-coder:1.5b

# 3. Start MSA backend (if needed for API-based tests)
cd backend
python -m uvicorn main:app --host 0.0.0.0 --port 8001
```

### Execute Full Benchmark Battery
```powershell
cd "E:\Final Year Project 1st prototype\LLM-Powered-Autonomous-Mobile-Application-Security-Penetration-Testing-Platform"
$env:PYTHONIOENCODING = "utf-8"
python benchmark\runners\master_runner.py
```

### Generate IEEE Reports
```powershell
python benchmark\reports\report_generator.py
```

## Output Files

| File | Description |
| :--- | :--- |
| `results/benchmark_summary.json` | Complete metrics for all 4 benchmark suites |
| `results/droidbench_results.csv` | Per-test DroidBench TP/FP/FN/TN |
| `results/ghera_results.csv` | Per-test Ghera detection results |
| `results/mastg_coverage_matrix.csv` | MASVS/MASTG verification matrix |
| `benchmark_results.db` | SQLite relational database (12 tables) |
| `reports/executive_summary.html` | Interactive HTML executive report |
| `reports/ieee_tables/*.md` | Publication-ready IEEE markdown tables |

## Configuration

Edit `benchmark/configs/benchmark_config.yaml` to enable/disable specific datasets.

## Environment Variables

```
LLM_PROVIDER=ollama
LLM_MODEL=qwen2.5-coder:1.5b
LLM_API_KEY=
LLM_FORCE_CPU=true
```

**WARNING:** Never store API keys or secrets in the repository.

## Ethical Notice

All benchmark targets are classified as BENCHMARK, AUTHORIZED, or RESEARCH_DATASET.
No unauthorized testing, exploitation, or attack was conducted against any third-party system.
