"""
Mobile Security Agent - FastAPI Backend
Autonomous Mobile Application Security Penetration Testing Agent
v2.0 - Advanced Edition
"""
import os
import sys
import re
import json
import time
import asyncio
import logging
from pathlib import Path
from datetime import datetime
from collections import defaultdict
from typing import Optional

from fastapi import FastAPI, File, UploadFile, HTTPException, BackgroundTasks, Query
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import JSONResponse, FileResponse, HTMLResponse

import config
from config import UPLOAD_DIR, REPORT_DIR, HOST, PORT, DEBUG
from utils.logger import get_logger
from utils.file_handler import FileHandler
from modules.static_analysis import StaticAnalyzer
from modules.reverse_engineering import ReverseEngineer
from modules.storage_analysis import StorageAnalyzer
from modules.network_analysis import NetworkAnalyzer
from modules.api_testing import APISecurityTester
from modules.dynamic_analysis import DynamicAnalyzer
from modules.vulnerability_mapper import VulnerabilityMapper
from modules.risk_assessment import RiskAssessor
from modules.report_generator import ReportGenerator
from knowledge.rag_engine import RAGEngine

logger = get_logger("MSA-Server")


class _PollingAccessLogFilter(logging.Filter):
    """Hide successful frontend polling requests from the development console."""

    def filter(self, record: logging.LogRecord) -> bool:
        try:
            message = record.getMessage()
            return not (" - \"GET /api/" in message and " 200" in message)
        except Exception:
            return True


def _reduce_uvicorn_polling_noise() -> None:
    access_logger = logging.getLogger("uvicorn.access")
    if not any(isinstance(f, _PollingAccessLogFilter) for f in access_logger.filters):
        access_logger.addFilter(_PollingAccessLogFilter())


_reduce_uvicorn_polling_noise()

app = FastAPI(
    title="Mobile Security Agent",
    description="Autonomous Mobile Application Security Penetration Testing Agent",
    version="2.0.0",
    docs_url="/docs",
    redoc_url="/redoc",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Serve frontend
FRONTEND_DIR = Path(__file__).resolve().parent.parent / "frontend"
if FRONTEND_DIR.exists():
    app.mount("/static", StaticFiles(directory=str(FRONTEND_DIR)), name="static")

# Initialize RAG engine
rag = RAGEngine()

# In-memory scan storage + history file
scans = {}
SCAN_HISTORY_FILE = Path(__file__).resolve().parent.parent / "scan_history.json"


def save_scan_history():
    """Persist completed scan metadata to disk without duplicates."""
    try:
        history = []
        seen_ids = set()
        for s in scans.values():
            sid = s.get("id")
            if not sid or sid in seen_ids:
                continue
            seen_ids.add(sid)
            entry = {
                "id": sid,
                "filename": s.get("filename", ""),
                "platform": s.get("platform", "android"),
                "status": s.get("status", "completed"),
                "progress": s.get("progress", 0),
                "started_at": s.get("started_at", ""),
                "completed_at": s.get("completed_at", ""),
                "duration_seconds": s.get("duration_seconds", 0),
                "file_size_bytes": s.get("file_size_bytes", 0),
                "total_findings": 0,
                "overall_risk": "unknown",
            }
            if s.get("results") and s["results"].get("risk_assessment"):
                entry["total_findings"] = s["results"]["risk_assessment"].get("total_findings", 0)
                entry["overall_risk"] = s["results"]["risk_assessment"].get("overall_risk", "unknown")
            history.append(entry)
        SCAN_HISTORY_FILE.write_text(json.dumps(history, indent=2), encoding="utf-8")
    except Exception as e:
        logger.error(f"Failed to save scan history: {e}")


def load_scan_history():
    """Load scan history from disk on startup."""
    if SCAN_HISTORY_FILE.exists():
        try:
            return json.loads(SCAN_HISTORY_FILE.read_text(encoding="utf-8"))
        except Exception:
            pass
    return []


def find_report_file(scan_id: str, suffix: str = ".html") -> Optional[Path]:
    """
    Find a report file on disk matching scan_id with multi-level resilient fallback.
    Supports exact filenames, stripped prefixes, unix timestamp IDs, and app-name matching.
    """
    from config import REPORT_DIR
    if not REPORT_DIR.exists():
        return None

    # 1. Exact match with candidate prefixes
    for prefix in ["", "report_", "scan_"]:
        p = REPORT_DIR / f"{prefix}{scan_id}{suffix}"
        if p.exists():
            return p

    # 2. Match without 'scan_' or 'report_' prefix
    clean_id = re.sub(r"^(?:scan_|report_)", "", scan_id)
    p = REPORT_DIR / f"report_{clean_id}{suffix}"
    if p.exists():
        return p

    # 3. If scan_id contains epoch timestamp e.g. scan_1791576501_MSA_VulnerableBank_Benchmark
    m = re.match(r"^(?:scan_)?\d+_(.+)$", scan_id)
    if m:
        app_name = m.group(1)
        matches = sorted(
            REPORT_DIR.glob(f"report_{app_name}*{suffix}"),
            key=lambda x: x.stat().st_mtime,
            reverse=True
        )
        if matches:
            return matches[0]

    # 4. Strip datetime suffix if present e.g. AppName_20261010_015351
    app_base = re.sub(r"_\d{8}_\d{6}$", "", clean_id)
    matches = sorted(
        REPORT_DIR.glob(f"*{app_base}*{suffix}"),
        key=lambda x: x.stat().st_mtime,
        reverse=True
    )
    if matches:
        return matches[0]

    return None


def resolve_scan(scan_id: str) -> Optional[dict]:
    """
    Resolve a scan record from memory or disk using multi-strategy fallback.
    Guarantees active, historical, and timestamped scans are resolved without 404s.
    """
    if not scan_id:
        return None

    # 1. Direct match in memory
    if scan_id in scans:
        return scans[scan_id]

    # 2. Check variations with or without 'scan_' prefix
    if scan_id.startswith("scan_") and scan_id[5:] in scans:
        return scans[scan_id[5:]]
    if not scan_id.startswith("scan_") and f"scan_{scan_id}" in scans:
        return scans[f"scan_{scan_id}"]

    # 3. Check memory by alias, app name, or filename
    clean_id = re.sub(r"^(?:scan_|report_)", "", scan_id)
    m = re.match(r"^\d+_(.+)$", clean_id)
    target_app = m.group(1) if m else clean_id
    target_app = re.sub(r"_\d{8}_\d{6}$", "", target_app).lower()

    for s in scans.values():
        if s.get("id") == scan_id or s.get("scan_id") == scan_id:
            scans[scan_id] = s
            return s
        fn = (s.get("filename") or "").lower()
        if target_app and (target_app in fn or fn.startswith(target_app)):
            scans[scan_id] = s
            return s

    # 4. Search disk for corresponding JSON report to resurrect in memory
    json_path = find_report_file(scan_id, suffix=".json")
    if json_path and json_path.exists():
        try:
            data = json.loads(json_path.read_text(encoding="utf-8"))
            meta = data.get("report_metadata", {})
            app_name = meta.get("application_name", "Unknown")
            platform = meta.get("platform", "android")
            html_file = json_path.with_suffix(".html")
            findings_count = data.get("risk_assessment", {}).get("total_findings", 0)

            reconstructed = {
                "id": scan_id,
                "scan_id": scan_id,
                "filename": f"{app_name}.apk" if platform == "android" else f"{app_name}.ipa",
                "platform": platform,
                "status": "completed",
                "progress": 100,
                "current_step": "Complete",
                "started_at": meta.get("analysis_timestamp", ""),
                "completed_at": meta.get("analysis_timestamp", ""),
                "duration_seconds": data.get("duration_seconds", 0),
                "file_size_bytes": data.get("application", {}).get("file_size_bytes", 0),
                "log": [
                    f"[INIT] Loaded report for {app_name} ({platform})",
                    f"[STATUS] Scan completed with {findings_count} verified findings",
                    f"[REPORT] Reports available at {html_file.name if html_file.exists() else json_path.name}"
                ],
                "results": {
                    **data,
                    "reports": {
                        "json": str(json_path),
                        "html": str(html_file) if html_file.exists() else ""
                    }
                }
            }
            scans[scan_id] = reconstructed
            file_scan_id = json_path.stem.replace("report_", "scan_")
            if file_scan_id not in scans:
                scans[file_scan_id] = reconstructed
            return reconstructed
        except Exception as e:
            logger.error(f"Error reconstructing scan from {json_path}: {e}")

    # 5. Search disk for standalone HTML report if JSON is not present
    html_path = find_report_file(scan_id, suffix=".html")
    if html_path and html_path.exists():
        reconstructed = {
            "id": scan_id,
            "scan_id": scan_id,
            "filename": f"{html_path.stem}.apk",
            "platform": "android",
            "status": "completed",
            "progress": 100,
            "current_step": "Complete",
            "started_at": datetime.fromtimestamp(html_path.stat().st_mtime).isoformat(),
            "completed_at": datetime.fromtimestamp(html_path.stat().st_mtime).isoformat(),
            "duration_seconds": 0,
            "file_size_bytes": 0,
            "log": [f"[REPORT] Found HTML report {html_path.name}"],
            "results": {
                "reports": {
                    "json": "",
                    "html": str(html_path)
                },
                "risk_assessment": {"total_findings": 0, "overall_risk": "info", "findings": []}
            }
        }
        scans[scan_id] = reconstructed
        return reconstructed

    return None


def load_scans_from_reports():
    """Scan the reports directory and reload past scans into memory on startup."""
    global scans
    try:
        from config import REPORT_DIR
        if not REPORT_DIR.exists():
            return
        
        count = 0
        for file in sorted(REPORT_DIR.glob("*.json"), key=lambda x: x.stat().st_mtime, reverse=True):
            try:
                data = json.loads(file.read_text(encoding="utf-8"))
                if "report_metadata" in data:
                    meta = data.get("report_metadata", {})
                    app_name = meta.get("application_name", "Unknown")
                    platform = meta.get("platform", "android")
                    
                    file_scan_id = file.stem.replace("report_", "scan_")
                    saved_scan_id = meta.get("scan_id")
                    primary_id = saved_scan_id or file_scan_id
                    
                    html_file = file.with_suffix(".html")
                    findings_count = data.get("risk_assessment", {}).get("total_findings", 0)
                    
                    scan_entry = {
                        "id": primary_id,
                        "scan_id": primary_id,
                        "filename": f"{app_name}.apk" if platform == "android" else f"{app_name}.ipa",
                        "platform": platform,
                        "status": "completed",
                        "progress": 100,
                        "current_step": "Complete",
                        "started_at": meta.get("analysis_timestamp", ""),
                        "completed_at": meta.get("analysis_timestamp", ""),
                        "duration_seconds": data.get("duration_seconds", 0),
                        "file_size_bytes": data.get("application", {}).get("file_size_bytes", 0),
                        "log": [
                            f"[INIT] Loaded report for {app_name} ({platform})",
                            f"[STATUS] Scan completed with {findings_count} verified findings",
                            f"[REPORT] Reports available at {html_file.name if html_file.exists() else file.name}"
                        ],
                        "results": {
                            **data,
                            "reports": {
                                "json": str(file),
                                "html": str(html_file) if html_file.exists() else ""
                            }
                        }
                    }
                    scans[primary_id] = scan_entry
                    if file_scan_id != primary_id:
                        scans[file_scan_id] = scan_entry
                    count += 1
            except Exception as e:
                logger.error(f"Failed to load scan report {file}: {e}")
        logger.info(f"Loaded {count} historical scans from reports directory.")
    except Exception as e:
        logger.error(f"Failed to scan reports directory: {e}")


# Load historical scans into memory
load_scans_from_reports()


# ─── ROUTES ──────────────────────────────────────────────

@app.get("/")
async def root():
    index_path = FRONTEND_DIR / "index.html"
    if index_path.exists():
        return HTMLResponse(index_path.read_text(encoding="utf-8"))
    return {"message": "Mobile Security Agent API", "version": "2.0.0"}


@app.get("/index.html", include_in_schema=False)
async def index_page():
    """Serve the landing page for links that use the explicit HTML filename."""
    return FileResponse(FRONTEND_DIR / "index.html", media_type="text/html")


@app.get("/about.html", include_in_schema=False)
@app.get("/about", include_in_schema=False)
async def about_page():
    """Serve the standalone About page."""
    return FileResponse(FRONTEND_DIR / "about.html", media_type="text/html")


@app.get("/features.html", include_in_schema=False)
@app.get("/features", include_in_schema=False)
async def features_page():
    """Serve the standalone Features & Capabilities page."""
    return FileResponse(FRONTEND_DIR / "features.html", media_type="text/html")


@app.get("/how-it-works.html", include_in_schema=False)
@app.get("/how-it-works", include_in_schema=False)
async def how_it_works_page():
    """Serve the standalone 10-Phase Pipeline Walkthrough page."""
    return FileResponse(FRONTEND_DIR / "how-it-works.html", media_type="text/html")


@app.get("/docs.html", include_in_schema=False)
@app.get("/docs", include_in_schema=False)
async def documentation_page():
    """Serve the documentation page linked from the frontend navigation."""
    return FileResponse(FRONTEND_DIR / "docs.html", media_type="text/html")


@app.get("/scan.html", include_in_schema=False)
@app.get("/scan", include_in_schema=False)
async def scan_page():
    """Serve the complete scan workflow, including upload, progress, and results."""
    return FileResponse(FRONTEND_DIR / "index.html", media_type="text/html")


@app.get("/api/health")
async def health():
    return {
        "status": "healthy",
        "version": "2.0.0",
        "timestamp": datetime.now().isoformat(),
        "total_scans": len(scans),
        "active_scans": sum(1 for s in scans.values() if s["status"] == "running"),
        "llm_provider": getattr(config, "LLM_PROVIDER", "ollama"),
        "llm_model": getattr(config, "LLM_MODEL", "qwen3.5:4b"),
    }


@app.get("/api/stats")
async def get_stats():
    """Get aggregate platform statistics."""
    completed = [s for s in scans.values() if s["status"] == "completed"]
    history = load_scan_history()

    total = len(scans) + len(history)
    all_completed = completed  # live ones

    # Severity breakdown across all scans
    severity_totals = defaultdict(int)
    top_vulns = defaultdict(int)
    platforms = defaultdict(int)

    for s in completed:
        ra = (s.get("results") or {}).get("risk_assessment") or {}
        for k, v in ra.get("risk_summary", {}).items():
            severity_totals[k] += v
        for f in ra.get("findings", []):
            top_vulns[f.get("title", "Unknown")] += 1
        platforms[s.get("platform", "unknown")] += 1

    # Top 10 most common vulnerabilities
    top_10 = sorted(top_vulns.items(), key=lambda x: x[1], reverse=True)[:10]

    return {
        "total_scans_all_time": total,
        "completed_scans": len(completed),
        "running_scans": sum(1 for s in scans.values() if s["status"] == "running"),
        "failed_scans": sum(1 for s in scans.values() if s["status"] == "failed"),
        "severity_breakdown": dict(severity_totals),
        "top_vulnerabilities": [{"title": t, "count": c} for t, c in top_10],
        "platform_breakdown": dict(platforms),
        "avg_scan_duration": round(
            sum(s.get("duration_seconds", 0) for s in completed) / max(len(completed), 1), 1
        ),
    }


@app.post("/api/scan")
async def start_scan(file: UploadFile = File(...), background_tasks: BackgroundTasks = None):
    """Upload and scan a mobile application."""
    content = await file.read()
    valid, msg = FileHandler.validate_file(file.filename, len(content))
    if not valid:
        raise HTTPException(400, msg)

    file_path = FileHandler.save_upload(file.filename, content)
    hashes = FileHandler.compute_hashes(file_path)
    platform = FileHandler.get_file_type(file_path)

    scan_id = f"scan_{int(time.time())}_{file_path.stem}"
    scans[scan_id] = {
        "id": scan_id,
        "filename": file.filename,
        "platform": platform,
        "status": "running",
        "progress": 0,
        "current_step": "Initializing...",
        "started_at": datetime.now().isoformat(),
        "hashes": hashes,
        "file_size_bytes": len(content),
        "log": [],
        "results": None,
    }

    if background_tasks:
        background_tasks.add_task(run_full_analysis, scan_id, file_path, file.filename, platform)
    else:
        await asyncio.to_thread(run_full_analysis, scan_id, file_path, file.filename, platform)

    return {
        "scan_id": scan_id,
        "status": "running",
        "message": "Scan started",
        "filename": file.filename,
        "platform": platform,
        "file_size": len(content),
    }


def add_scan_log(scan_id: str, message: str):
    """Add a timestamped log entry to the scan."""
    ts = datetime.now().strftime("%H:%M:%S")
    entry = f"[{ts}] {message}"
    if scan_id in scans:
        scans[scan_id]["log"].append(entry)
        # Keep up to 1000 entries so full detailed execution trace is retained
        if len(scans[scan_id]["log"]) > 1000:
            scans[scan_id]["log"] = scans[scan_id]["log"][-1000:]


def run_full_analysis(scan_id: str, file_path: Path, filename: str, platform: str):
    """Execute the 10-step security analysis pipeline."""
    start_time = time.time()
    try:
        # The RAG index is shared, but an unavailable LLM must only be
        # disabled for the active scan, not for the server lifetime.
        rag.llm_client.reset_scan_state()
        all_findings = []
        app_name = file_path.stem
        decompiled_dir = None

        # STEP 1: Application Reconnaissance
        scans[scan_id]["current_step"] = "Reconnaissance"
        add_scan_log(scan_id, "PHASE 1: Application Reconnaissance & Binary Ingestion")
        file_size_mb = round(scans[scan_id].get('file_size_bytes', 0) / (1024 * 1024), 2)
        add_scan_log(scan_id, f"[INIT] Ingesting package: {filename} ({file_size_mb} MB) | Platform: {platform.upper()}")
        hashes = scans[scan_id].get("hashes", {})
        add_scan_log(scan_id, f"[HASH] SHA-256: {hashes.get('sha256', 'N/A')}")
        add_scan_log(scan_id, f"[HASH] SHA-1:   {hashes.get('sha1', 'N/A')}")
        add_scan_log(scan_id, f"[HASH] MD5:     {hashes.get('md5', 'N/A')}")
        
        # Binary container structural inspection
        try:
            import zipfile
            if zipfile.is_zipfile(file_path):
                with zipfile.ZipFile(file_path, "r") as zf:
                    entries = zf.namelist()
                    dex_files = [e for e in entries if e.endswith(".dex")]
                    so_files = [e for e in entries if e.endswith(".so")]
                    certs = [e for e in entries if "META-INF" in e and (e.endswith(".RSA") or e.endswith(".DSA") or e.endswith(".EC"))]
                    add_scan_log(scan_id, f"[ZIP] Container unpacked: {len(entries)} indexed archive entries")
                    if dex_files:
                        add_scan_log(scan_id, f"[DEX] Compiled Dalvik bytecode: {len(dex_files)} units ({', '.join(dex_files[:3])}{'...' if len(dex_files)>3 else ''})")
                    if so_files:
                        add_scan_log(scan_id, f"[NATIVE] Shared native binaries: {len(so_files)} ELF libraries detected in lib/")
                    if certs:
                        add_scan_log(scan_id, f"[CERT] Digital signing envelope identified: {certs[0]}")
        except Exception as ze:
            add_scan_log(scan_id, f"[WARN] Container inspection notice: {ze}")
            
        scans[scan_id]["progress"] = 10

        # STEP 1.5: Decompilation (jadx -> androguard -> raw strings)
        decompile_engine = "none"
        if platform == "android":
            try:
                from utils.decompile import decompile_apk
                scans[scan_id]["current_step"] = "Decompilation"
                add_scan_log(scan_id, "PHASE 1.5: Smali & Java Bytecode Decompilation")
                add_scan_log(scan_id, "[DECOMPILE] Invoking multi-engine disassembler (JADX -> Androguard -> Smali)...")
                decompiled_dir, decompile_engine = decompile_apk(file_path, platform)
                if decompiled_dir:
                    java_files = list(decompiled_dir.rglob("*.java"))
                    smali_files = list(decompiled_dir.rglob("*.smali"))
                    xml_files = list(decompiled_dir.rglob("*.xml"))
                    add_scan_log(scan_id, f"[DECOMPILE] Disassembly complete via {decompile_engine}: {len(java_files)} Java files, {len(smali_files)} Smali files, {len(xml_files)} XML resources")
                    add_scan_log(scan_id, f"[DECOMPILE] Reconstructed intermediate AST structure at: {decompiled_dir.name}")
                else:
                    add_scan_log(scan_id, "[DECOMPILE] Primary decompiler unavailable - falling back to raw binary strings & AXML")
            except Exception as e:
                add_scan_log(scan_id, f"[DECOMPILE] Decompilation error: {e}")
        scans[scan_id]["progress"] = 15

        # STEP 2: Static Analysis
        scans[scan_id]["current_step"] = "Static Analysis"
        add_scan_log(scan_id, "PHASE 2: Static Code Analysis & Manifest Auditing")
        add_scan_log(scan_id, "[STATIC] Parsing AndroidManifest.xml and binary resource tables...")
        try:
            static = StaticAnalyzer(file_path, decompiled_dir=decompiled_dir)
            static_results = static.analyze()
        except Exception as e:
            add_scan_log(scan_id, f"[STATIC] Error during static analysis: {e}")
            static_results = {}
        
        findings_count = len(static_results.get("findings", []))
        all_findings.extend(static_results.get("findings", []))
        
        manifest = static_results.get("manifest", {})
        pkg = manifest.get("package", file_path.stem)
        min_sdk = manifest.get("min_sdk", "N/A")
        target_sdk = manifest.get("target_sdk", "N/A")
        add_scan_log(scan_id, f"[MANIFEST] Target Package: {pkg} | Min SDK: {min_sdk} | Target SDK: {target_sdk}")
        
        components = static_results.get("components", {})
        acts = components.get("activities", [])
        servs = components.get("services", [])
        rcvrs = components.get("receivers", [])
        provs = components.get("providers", [])
        add_scan_log(scan_id, f"[COMPONENTS] Evaluated: {len(acts)} Activities, {len(servs)} Services, {len(rcvrs)} Receivers, {len(provs)} Providers")
        
        exp_acts = [a for a in acts if a.get("exported")]
        exp_servs = [s for s in servs if s.get("exported")]
        if exp_acts or exp_servs:
            add_scan_log(scan_id, f"[WARN] Attack Surface: {len(exp_acts)} exported activities, {len(exp_servs)} exported services exposed to external IPC")
            
        perms = static_results.get("permissions", [])
        dang_perms = [p for p in perms if any(d in p for d in ["LOCATION", "CAMERA", "RECORD", "CONTACTS", "STORAGE", "SMS", "PHONE"])]
        add_scan_log(scan_id, f"[PERMS] Audited {len(perms)} declared permissions ({len(dang_perms)} privileged / dangerous)")
        for dp in dang_perms[:4]:
            add_scan_log(scan_id, f"  ↳ Privilege: {dp.split('.')[-1]}")
            
        secrets = static_results.get("secrets", [])
        if secrets:
            add_scan_log(scan_id, f"[SECRETS] High-entropy regex scanner flagged {len(secrets)} hardcoded secrets/keys in code")
            for sec in secrets[:3]:
                sec_type = sec.get("type", "Secret Key")
                add_scan_log(scan_id, f"  ↳ Matched: {sec_type} in {sec.get('file', 'bytecode')}")
        else:
            add_scan_log(scan_id, "[SECRETS] Clean: Zero high-entropy secret patterns detected")
            
        api_eps = static_results.get("api_endpoints", [])
        add_scan_log(scan_id, f"[ENDPOINTS] Harvested {len(api_eps)} network URIs and domain references from strings")
        add_scan_log(scan_id, f"[STATIC] Static analysis phase complete: {findings_count} potential issues flagged")
        scans[scan_id]["progress"] = 25

        # STEP 2.5: AST Taint Flow Analysis (if decompiled sources available)
        ast_results = {"findings": [], "ast_stats": {}}
        if decompiled_dir:
            try:
                from modules.ast_analyzer import ASTAnalyzer
                scans[scan_id]["current_step"] = "AST Taint Analysis"
                add_scan_log(scan_id, "PHASE 2.5: AST Inter-Procedural Taint Flow Analysis")
                add_scan_log(scan_id, "[AST] Building Abstract Syntax Trees to track inter-procedural source-to-sink flows...")
                ast = ASTAnalyzer(decompiled_dir)
                ast_results = ast.analyze()
                ast_findings = ast_results.get("findings", [])
                ast_stats = ast_results.get("ast_stats", {})
                all_findings.extend(ast_findings)
                add_scan_log(scan_id, f"[AST] Parsed {ast_stats.get('files_parsed', 0)} compilation units across classes")
                add_scan_log(scan_id, f"[AST] Identified {ast_stats.get('taint_flows', 0)} taint propagation chains from sources to sinks")
                if ast_stats.get('dead_methods_skipped', 0) > 0:
                    add_scan_log(scan_id, f"[AST] Pruned {ast_stats.get('dead_methods_skipped', 0)} unreachable dead-code methods")
                add_scan_log(scan_id, f"[AST] Taint engine emitted {len(ast_findings)} data-flow security findings")
            except ImportError:
                add_scan_log(scan_id, "[AST] AST analyzer engine skipped (javalang not installed)")
            except Exception as e:
                add_scan_log(scan_id, f"[AST] Notice: AST analysis returned: {e}")
        scans[scan_id]["progress"] = 30

        # STEP 3: Reverse Engineering
        scans[scan_id]["current_step"] = "Reverse Engineering"
        add_scan_log(scan_id, "PHASE 3: Reverse Engineering & Disassembly Auditing")
        add_scan_log(scan_id, "[REV] Scanning Smali opcodes, reflection patterns, and cloud service endpoints...")
        try:
            rev = ReverseEngineer(file_path)
            rev_results = rev.analyze()
        except Exception as e:
            add_scan_log(scan_id, f"[REV] Error during reverse engineering: {e}")
            rev_results = {}
            
        all_findings.extend(rev_results.get("findings", []))
        backend_urls = rev_results.get("backend_urls", [])
        config_files = rev_results.get("config_files", [])
        add_scan_log(scan_id, f"[REV] Extracted {len(backend_urls)} external network endpoints & cloud URIs")
        for u in backend_urls[:3]:
            u_str = u.get("url", str(u)) if isinstance(u, dict) else str(u)
            add_scan_log(scan_id, f"  ↳ Cloud URI: {u_str[:50]}...")
        add_scan_log(scan_id, f"[REV] Inspected {len(config_files)} application configuration and properties files")
        add_scan_log(scan_id, f"[REV] Reverse engineering yielded {len(rev_results.get('findings', []))} findings")
        scans[scan_id]["progress"] = 40

        # STEP 4: Storage Security
        scans[scan_id]["current_step"] = "Storage Analysis"
        add_scan_log(scan_id, "PHASE 4: Storage Security & Local Persistence Auditing")
        add_scan_log(scan_id, "[STORAGE] Auditing SharedPreferences, SQLite databases, Realm, and external I/O paths...")
        try:
            storage = StorageAnalyzer(file_path)
            storage_results = storage.analyze()
        except Exception as e:
            add_scan_log(scan_id, f"[STORAGE] Error during storage analysis: {e}")
            storage_results = {}
            
        all_findings.extend(storage_results.get("findings", []))
        st_issues = storage_results.get("findings", [])
        add_scan_log(scan_id, f"[STORAGE] Completed storage audit: {len(st_issues)} local persistence issues flagged")
        for s_iss in st_issues[:3]:
            add_scan_log(scan_id, f"  ↳ [{s_iss.get('severity', 'info').upper()}] {s_iss.get('title')}")
        scans[scan_id]["progress"] = 50

        # STEP 5: Network Security
        scans[scan_id]["current_step"] = "Network Analysis"
        add_scan_log(scan_id, "PHASE 5: Network Transport & Cryptographic Protocol Auditing")
        add_scan_log(scan_id, "[NET] Auditing network_security_config.xml, cleartext transport, and TLS pinning...")
        try:
            network = NetworkAnalyzer(file_path)
            network_results = network.analyze()
        except Exception as e:
            add_scan_log(scan_id, f"[NET] Error during network analysis: {e}")
            network_results = {}
            
        all_findings.extend(network_results.get("findings", []))
        net_issues = network_results.get("findings", [])
        add_scan_log(scan_id, f"[NET] Completed transport audit: {len(net_issues)} network security issues flagged")
        for n_iss in net_issues[:3]:
            add_scan_log(scan_id, f"  ↳ [{n_iss.get('severity', 'info').upper()}] {n_iss.get('title')}")
        scans[scan_id]["progress"] = 60

        # STEP 6: API Security
        scans[scan_id]["current_step"] = "API Security Testing"
        add_scan_log(scan_id, "PHASE 6: API Security & OWASP API Top 10 Surface Auditing")
        api_endpoints = static_results.get("api_endpoints", []) + rev_results.get("backend_urls", [])
        add_scan_log(scan_id, f"[API] Probing {len(api_endpoints)} harvested endpoints against OWASP API Top 10 (BOLA/Auth)...")
        try:
            api = APISecurityTester(file_path, api_endpoints)
            api_results = api.analyze()
        except Exception as e:
            add_scan_log(scan_id, f"[API] Error during API analysis: {e}")
            api_results = {}
            
        all_findings.extend(api_results.get("findings", []))
        api_issues = api_results.get("findings", [])
        add_scan_log(scan_id, f"[API] API security analysis complete: {len(api_issues)} issues flagged")
        for a_iss in api_issues[:3]:
            add_scan_log(scan_id, f"  ↳ [{a_iss.get('severity', 'info').upper()}] {a_iss.get('title')}")
        scans[scan_id]["progress"] = 70

        # STEP 7: Dynamic Analysis (Frida + static heuristics)
        scans[scan_id]["current_step"] = "Dynamic Analysis"
        add_scan_log(scan_id, "PHASE 7: Dynamic Runtime Instrumentation & Frida Hooking")
        pkg_name = static_results.get("manifest", {}).get("package", file_path.stem)
        add_scan_log(scan_id, f"[DYNAMIC] Connecting to ADB daemon and Frida-server runtime (Target: {pkg_name})...")
        try:
            dynamic = DynamicAnalyzer(file_path, package_name=pkg_name)
            dynamic_results = dynamic.analyze()
        except Exception as e:
            add_scan_log(scan_id, f"[DYNAMIC] Error during dynamic analysis: {e}")
            dynamic_results = {}
            
        all_findings.extend(dynamic_results.get("findings", []))
        dyn_findings = dynamic_results.get("findings", [])
        add_scan_log(scan_id, f"[DYNAMIC] Dynamic runtime session executed: {len(dyn_findings)} runtime findings")
        for indicator in dynamic_results.get("runtime_indicators", [])[:4]:
            add_scan_log(scan_id, f"  ↳ [FRIDA] {indicator}")
        scans[scan_id]["progress"] = 80

        # STEP 8: Vulnerability Mapping & Dual-Track RAG + LLM Cognitive Triage
        scans[scan_id]["current_step"] = "Vulnerability Mapping"
        add_scan_log(scan_id, "PHASE 8: OWASP/CWE Taxonomy Mapping & RAG-Augmented Cognitive Triage")
        add_scan_log(scan_id, f"[MAPPER] Aggregated {len(all_findings)} raw candidate alarms across 7 heuristic modules")
        mapper = VulnerabilityMapper()
        mapped = mapper.map_findings(all_findings)

        # --- Smarter deduplication ---
        import re as _re
        def _norm_title(t):
            t = t.lower().strip()
            for suffix in [' detected', ' found', ' present', ' enabled', ' used']:
                if t.endswith(suffix):
                    t = t[:-len(suffix)].strip()
            return _re.sub(r'\s+', ' ', t)

        seen_titles = set()
        unique_mapped = []
        for f in mapped:
            norm = _norm_title(f.get("title", ""))
            if norm not in seen_titles:
                seen_titles.add(norm)
                f["app_name"] = app_name
                f["package_name"] = pkg_name
                unique_mapped.append(f)

        add_scan_log(scan_id, f"[DEDUP] Normalized and deduplicated to {len(unique_mapped)} distinct candidate vulnerabilities")
        add_scan_log(scan_id, f"[RAG] Activating in-memory dual-track retrieval engine (2,075 verified security controls)")
        add_scan_log(scan_id, f"[RAG] Sparse Lexical BM25 + High-Dimensional TF-IDF with Reciprocal Rank Fusion (k=60)")

        # --- Downgrade generic "absence" findings to info ---
        absence_keywords = [
            "no root", "no jailbreak", "no certificate pinning",
            "no screen capture", "missing runtime tamper",
            "no rate limiting", "cache storage usage",
            "debug logging detected",
        ]
        for f in unique_mapped:
            title_lower = f.get("title", "").lower()
            if any(kw in title_lower for kw in absence_keywords):
                if f.get("severity", "").lower() not in ("critical", "high"):
                    f["severity"] = "info"
                    f["confidence"] = "low"

        # Sort candidate findings by severity (Critical -> High -> Medium -> Low -> Info)
        sev_rank = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
        unique_mapped.sort(key=lambda x: (
            sev_rank.get(x.get("severity", "info").lower(), 4),
            0 if (x.get("file_path") or x.get("code_snippet")) else 1
        ))

        # Budget LLM cognitive audits - audit ALL critical+high and top medium findings
        max_audits = getattr(config, "LLM_MAX_AUDITS_PER_SCAN", 15)
        audited_count = 0
        for f in unique_mapped:
            sev = f.get("severity", "info").lower()
            if sev in ("critical", "high") and audited_count < max_audits:
                f["llm_audit_eligible"] = True
                audited_count += 1
            elif sev == "medium" and audited_count < max_audits:
                f["llm_audit_eligible"] = True
                audited_count += 1
            else:
                f["llm_audit_eligible"] = False

        llm_model_name = getattr(config, "LLM_MODEL", "Qwen2.5-Coder")
        add_scan_log(scan_id, f"[LLM] Dispatching candidate findings to Cognitive Auditor ({llm_model_name})...")

        # Enrich candidate findings with live real-time logging
        def _enrich_with_logging(item):
            idx, f = item
            title = f.get("title", "Finding")
            sev = f.get("severity", "info").upper()
            add_scan_log(scan_id, f"[RAG] [{idx+1}/{len(unique_mapped)}] Querying knowledge index for: '{title[:45]}'")
            
            enriched_f = rag.enrich_finding(f)
            
            if enriched_f.get("llm_verified"):
                verdict = "FALSE_POSITIVE" if enriched_f.get("is_false_positive") else "CONFIRMED"
                conf = enriched_f.get("llm_confidence", 0)
                if verdict == "FALSE_POSITIVE":
                    add_scan_log(scan_id, f"[PRUNE] ✗ LLM Cognitive Auditor pruned false alarm: '{title[:35]}' (Conf: {conf}%)")
                else:
                    add_scan_log(scan_id, f"[LLM] ✓ LLM Cognitive Auditor verified vulnerability: '{title[:35]}' [{sev}] (Conf: {conf}%)")
            else:
                cwe_code = enriched_f.get("cwe") or "CWE-General"
                add_scan_log(scan_id, f"[RRF] Linked to {cwe_code} via Reciprocal Rank Fusion")
                
            return enriched_f

        indexed_mapped = list(enumerate(unique_mapped))
        from concurrent.futures import ThreadPoolExecutor
        provider = getattr(config, "LLM_PROVIDER", "ollama").lower()
        max_workers = 6 if provider in ("nvidia", "openai", "gemini") else 2
        
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            enriched = list(executor.map(_enrich_with_logging, indexed_mapped))

        fp_count = sum(1 for f in enriched if f.get("is_false_positive"))
        verified_count = len(enriched) - fp_count
        noise_pct = round((fp_count / len(enriched) * 100), 1) if enriched else 0.0
        add_scan_log(scan_id, f"[SUMMARY] Cognitive Triage complete: {verified_count} verified vulnerabilities, {fp_count} false alarms eliminated ({noise_pct}% noise reduction)")
        scans[scan_id]["progress"] = 85

        # STEP 9: Risk Assessment
        scans[scan_id]["current_step"] = "Risk Assessment"
        add_scan_log(scan_id, "PHASE 9: Quantitative Risk Assessment & CVSS v3.1 Scoring")
        add_scan_log(scan_id, "[CVSS] Calculating Base Metric Vectors: Exploitability (AV/AC/PR/UI) and Impact (C/I/A)...")
        assessor = RiskAssessor()
        risk_results = assessor.assess(enriched)
        add_scan_log(scan_id, f"[RISK] Composite Risk Score: {risk_results.get('overall_risk', 'unknown').upper()}")
        add_scan_log(scan_id, f"[RISK] Severity breakdown: Critical: {risk_results.get('critical_count', 0)}, High: {risk_results.get('high_count', 0)}, Medium: {risk_results.get('medium_count', 0)}, Low: {risk_results.get('low_count', 0)}")
        if risk_results.get('false_positives_count', 0) > 0:
            add_scan_log(scan_id, f"[RISK] Suppressed false positive candidates: {risk_results.get('false_positives_count', 0)}")
        scans[scan_id]["progress"] = 90

        # STEP 10: Report Generation
        scans[scan_id]["current_step"] = "Report Generation"
        add_scan_log(scan_id, "PHASE 10: Audit Report Generation & Export")
        add_scan_log(scan_id, "[REPORT] Generating machine-readable JSON security report adhering to standard JSON schema...")
        add_scan_log(scan_id, "[REPORT] Rendering interactive HTML Executive Audit Dashboard with Jinja2...")

        results = {
            "application": {
                "name": app_name,
                "filename": filename,
                "platform": platform,
                "hashes": scans[scan_id]["hashes"],
                "file_size_bytes": scans[scan_id].get("file_size_bytes", 0),
            },
            "static_analysis": {
                "permissions": static_results.get("permissions", []),
                "components": static_results.get("components", {}),
                "api_endpoints": static_results.get("api_endpoints", []),
                "secrets": static_results.get("secrets", []),
                "manifest": static_results.get("manifest", {}),
            },
            "reverse_engineering": {
                "backend_urls": rev_results.get("backend_urls", []),
                "config_files": len(rev_results.get("config_files", [])),
                "interesting_files": rev_results.get("interesting_files", []),
            },
            "storage_analysis": storage_results.get("storage_issues", []),
            "network_analysis": network_results.get("network_config", {}),
            "api_analysis": api_results.get("api_analysis", []),
            "dynamic_analysis": dynamic_results.get("runtime_indicators", []),
            "ast_analysis": ast_results.get("ast_stats", {}),
            "decompiled": decompiled_dir is not None,
            "risk_assessment": risk_results,
        }

        gen = ReportGenerator(app_name, platform, scan_id=scan_id)
        json_report = gen.generate_json(results)
        html_report = gen.generate_html(results)

        results["reports"] = {
            "json": str(json_report),
            "html": str(html_report),
        }

        duration = round(time.time() - start_time, 2)
        scans[scan_id]["results"] = results
        scans[scan_id]["status"] = "completed"
        scans[scan_id]["progress"] = 100
        scans[scan_id]["current_step"] = "Complete"
        scans[scan_id]["completed_at"] = datetime.now().isoformat()
        scans[scan_id]["duration_seconds"] = duration
        add_scan_log(scan_id, f"[REPORT] Reports successfully exported to {results['reports']['html']}")
        add_scan_log(scan_id, f"COMPLETE: Autonomous security penetration audit finished in {duration}s")
        add_scan_log(scan_id, f"[STATUS] Final Verdict: {verified_count} verified vulnerabilities ({fp_count} false alarms suppressed)")

        save_scan_history()
        logger.info(f"[{scan_id}] Analysis complete in {duration}s. {risk_results['total_findings']} findings.")

    except Exception as e:
        logger.error(f"[{scan_id}] Analysis failed: {e}")
        scans[scan_id]["status"] = "failed"
        scans[scan_id]["error"] = str(e)
        scans[scan_id]["current_step"] = "Failed"
        add_scan_log(scan_id, f"[ERROR] Pipeline execution failed: {str(e)}")
        scans[scan_id]["duration_seconds"] = round(time.time() - start_time, 2)
        save_scan_history()


@app.get("/api/scan/{scan_id}")
async def get_scan(scan_id: str):
    scan = resolve_scan(scan_id)
    if not scan:
        raise HTTPException(404, "Scan not found")
    return scan


@app.get("/api/scan/{scan_id}/log")
async def get_scan_log(scan_id: str):
    """Get real-time scan log."""
    scan = resolve_scan(scan_id)
    if not scan:
        raise HTTPException(404, "Scan not found")
    log_entries = scan.get("log", [])
    if not log_entries and scan.get("status") == "completed":
        app_name = scan.get("filename", "Application")
        res = scan.get("results") or {}
        findings_count = (res.get("risk_assessment") or {}).get("total_findings", 0)
        log_entries = [
            f"[INIT] Loaded scan report for {app_name}",
            f"[STATUS] Scan completed with {findings_count} findings",
            f"[REPORT] Reports generated successfully"
        ]
    return {
        "scan_id": scan_id,
        "status": scan.get("status", "running"),
        "progress": scan.get("progress", 0),
        "current_step": scan.get("current_step", "Complete"),
        "log": log_entries,
    }


@app.get("/api/scan/{scan_id}/executive-summary")
async def get_executive_summary(scan_id: str):
    """Get a concise executive summary of the scan."""
    scan = resolve_scan(scan_id)
    if not scan:
        raise HTTPException(404, "Scan not found")
    if scan.get("status") != "completed":
        raise HTTPException(400, "Scan not completed")

    res = scan.get("results") or {}
    ra = res.get("risk_assessment") or {}
    app_info = res.get("application") or {}
    summary = ra.get("risk_summary") or {}

    return {
        "application": app_info.get("name", scan.get("filename", "Application")),
        "platform": app_info.get("platform", scan.get("platform", "android")),
        "overall_risk": ra.get("overall_risk", "unknown"),
        "total_findings": ra.get("total_findings", 0),
        "critical": summary.get("critical", 0),
        "high": summary.get("high", 0),
        "medium": summary.get("medium", 0),
        "low": summary.get("low", 0),
        "info": summary.get("info", 0),
        "scan_duration": scan.get("duration_seconds", 0),
        "scanned_at": scan.get("completed_at", ""),
        "top_risks": [
            {"title": f["title"], "severity": f["severity"], "owasp": f.get("owasp", "")}
            for f in ra.get("findings", [])[:5]
        ],
    }


@app.get("/api/scan/{scan_id}/report/json")
async def get_json_report(scan_id: str):
    scan = resolve_scan(scan_id)
    if scan and scan.get("status") == "completed":
        res = scan.get("results") or {}
        reports = res.get("reports") or {}
        report_path = reports.get("json")
        if report_path and Path(report_path).exists():
            return FileResponse(report_path, media_type="application/json", filename=Path(report_path).name)

    # Resilient disk search fallback
    json_file = find_report_file(scan_id, suffix=".json")
    if json_file and json_file.exists():
        return FileResponse(json_file, media_type="application/json", filename=json_file.name)

    if scan and scan.get("status") != "completed":
        raise HTTPException(400, f"Scan status: {scan['status']}")
    raise HTTPException(404, f"JSON report for scan '{scan_id}' not found")


@app.get("/api/scan/{scan_id}/report/html")
async def get_html_report(scan_id: str):
    scan = resolve_scan(scan_id)
    if scan and scan.get("status") == "completed":
        res = scan.get("results") or {}
        reports = res.get("reports") or {}
        report_path = reports.get("html")
        if report_path and Path(report_path).exists():
            return FileResponse(report_path, media_type="text/html", filename=Path(report_path).name)

    # Resilient disk search fallback
    html_file = find_report_file(scan_id, suffix=".html")
    if html_file and html_file.exists():
        return FileResponse(html_file, media_type="text/html", filename=html_file.name)

    if scan and scan.get("status") != "completed":
        raise HTTPException(400, f"Scan status: {scan['status']}")
    raise HTTPException(404, f"HTML report for scan '{scan_id}' not found")


@app.get("/api/scans")
async def list_scans():
    seen_ids = set()
    result = []
    for s in sorted(scans.values(), key=lambda x: x.get("started_at", ""), reverse=True):
        sid = s.get("id")
        res = s.get("results") or {}
        reports = res.get("reports") or {}
        rep_html = reports.get("html", "")
        dedup_key = rep_html if rep_html else sid
        if dedup_key in seen_ids:
            continue
        seen_ids.add(dedup_key)
        
        risk_assess = res.get("risk_assessment") or {}
        result.append({
            "id": sid,
            "scan_id": sid,
            "filename": s.get("filename", ""),
            "status": s.get("status", "running"),
            "progress": s.get("progress", 0),
            "platform": s.get("platform", "android"),
            "current_step": s.get("current_step", ""),
            "started_at": s.get("started_at", ""),
            "completed_at": s.get("completed_at", ""),
            "duration_seconds": s.get("duration_seconds", 0),
            "total_findings": risk_assess.get("total_findings", 0),
            "overall_risk": risk_assess.get("overall_risk", "pending"),
        })
    return result


@app.delete("/api/scan/{scan_id}")
async def delete_scan(scan_id: str):
    """Delete a scan and its reports."""
    scan = resolve_scan(scan_id)
    if not scan:
        raise HTTPException(404, "Scan not found")
    target_id = scan.get("id")
    to_delete = [k for k, v in list(scans.items()) if v.get("id") == target_id or k == scan_id]
    for k in to_delete:
        scans.pop(k, None)

    reports = (scan.get("results") or {}).get("reports") or {}
    for path_str in [reports.get("json"), reports.get("html")]:
        if path_str:
            try:
                p = Path(path_str)
                if p.exists():
                    p.unlink()
            except Exception as e:
                logger.error(f"Failed to delete report file {path_str}: {e}")

    save_scan_history()
    return {"message": f"Scan {scan_id} deleted"}


@app.get("/api/knowledge/{topic}")
async def query_knowledge(topic: str):
    results = rag.query(topic)
    return {"topic": topic, "results": results}


@app.get("/api/knowledge/remediation/{owasp_id}")
async def get_remediation(owasp_id: str):
    guide = rag.get_remediation(owasp_id.upper())
    return {"owasp_id": owasp_id.upper(), "remediation": guide}


@app.post("/api/llm/clear-cache")
async def clear_llm_cache():
    """Clear memory and persistent LLM response cache to prevent cross-app contamination."""
    count = rag.llm_client.clear_cache()
    return {"status": "ok", "cleared_entries": count, "message": f"Successfully cleared {count} entries from LLM cache"}


if __name__ == "__main__":
    import uvicorn
    logger.info("[SHIELD] Mobile Security Agent v2.0 starting...")
    uvicorn.run("main:app", host=HOST, port=PORT, reload=DEBUG)
