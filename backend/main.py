"""
Mobile Security Agent - FastAPI Backend
Autonomous Mobile Application Security Penetration Testing Agent
v2.0 - Advanced Edition
"""
import os
import sys
import json
import time
import asyncio
from pathlib import Path
from datetime import datetime
from collections import defaultdict

from fastapi import FastAPI, File, UploadFile, HTTPException, BackgroundTasks, Query
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import JSONResponse, FileResponse, HTMLResponse

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
    """Persist completed scan metadata to disk."""
    try:
        history = []
        for s in scans.values():
            entry = {
                "id": s["id"],
                "filename": s["filename"],
                "platform": s["platform"],
                "status": s["status"],
                "progress": s["progress"],
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


# ─── ROUTES ──────────────────────────────────────────────

@app.get("/")
async def root():
    index_path = FRONTEND_DIR / "index.html"
    if index_path.exists():
        return HTMLResponse(index_path.read_text(encoding="utf-8"))
    return {"message": "Mobile Security Agent API", "version": "2.0.0"}


@app.get("/api/health")
async def health():
    return {
        "status": "healthy",
        "version": "2.0.0",
        "timestamp": datetime.now().isoformat(),
        "total_scans": len(scans),
        "active_scans": sum(1 for s in scans.values() if s["status"] == "running"),
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
        ra = s.get("results", {}).get("risk_assessment", {})
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
        # Keep only last 50 entries
        if len(scans[scan_id]["log"]) > 50:
            scans[scan_id]["log"] = scans[scan_id]["log"][-50:]


def run_full_analysis(scan_id: str, file_path: Path, filename: str, platform: str):
    """Execute the 10-step security analysis pipeline."""
    start_time = time.time()
    try:
        all_findings = []
        app_name = file_path.stem
        decompiled_dir = None

        # STEP 1: Application Reconnaissance
        scans[scan_id]["current_step"] = "Reconnaissance"
        add_scan_log(scan_id, "PHASE 1: Application Reconnaissance")
        add_scan_log(scan_id, f"Target: {filename} | Platform: {platform}")
        add_scan_log(scan_id, f"SHA-256: {scans[scan_id]['hashes'].get('sha256', 'N/A')[:32]}...")
        scans[scan_id]["progress"] = 10

        # STEP 1.5: Decompilation (jadx -> androguard -> raw strings)
        decompile_engine = "none"
        if platform == "android":
            try:
                from utils.decompile import decompile_apk
                scans[scan_id]["current_step"] = "Decompilation"
                add_scan_log(scan_id, "PHASE 1.5: APK Decompilation")
                decompiled_dir, decompile_engine = decompile_apk(file_path, platform)
                if decompiled_dir:
                    java_count = len(list(decompiled_dir.rglob("*.java")))
                    add_scan_log(scan_id, f"  Decompiled via {decompile_engine}: {java_count} Java source files")
                else:
                    add_scan_log(scan_id, "  No decompiler available — using raw strings")
            except Exception as e:
                add_scan_log(scan_id, f"  Decompilation error: {e}")
        scans[scan_id]["progress"] = 15

        # STEP 2: Static Analysis
        scans[scan_id]["current_step"] = "Static Analysis"
        add_scan_log(scan_id, "PHASE 2: Static Code Analysis")
        static = StaticAnalyzer(file_path, decompiled_dir=decompiled_dir)
        static_results = static.analyze()
        findings_count = len(static_results.get("findings", []))
        all_findings.extend(static_results.get("findings", []))
        add_scan_log(scan_id, f"  Found {findings_count} static issues")
        add_scan_log(scan_id, f"  Permissions: {len(static_results.get('permissions', []))}")
        add_scan_log(scan_id, f"  Secrets: {len(static_results.get('secrets', []))}")
        add_scan_log(scan_id, f"  API Endpoints: {len(static_results.get('api_endpoints', []))}")
        scans[scan_id]["progress"] = 25

        # STEP 2.5: AST Taint Flow Analysis (if decompiled sources available)
        ast_results = {"findings": [], "ast_stats": {}}
        if decompiled_dir:
            try:
                from modules.ast_analyzer import ASTAnalyzer
                scans[scan_id]["current_step"] = "AST Taint Analysis"
                add_scan_log(scan_id, "PHASE 2.5: AST Taint Flow Analysis")
                ast = ASTAnalyzer(decompiled_dir)
                ast_results = ast.analyze()
                ast_findings = ast_results.get("findings", [])
                ast_stats = ast_results.get("ast_stats", {})
                all_findings.extend(ast_findings)
                add_scan_log(scan_id, f"  Files parsed: {ast_stats.get('files_parsed', 0)}")
                add_scan_log(scan_id, f"  Taint flows found: {ast_stats.get('taint_flows', 0)}")
                add_scan_log(scan_id, f"  Dead methods skipped: {ast_stats.get('dead_methods_skipped', 0)}")
                add_scan_log(scan_id, f"  AST findings: {len(ast_findings)}")
            except ImportError:
                add_scan_log(scan_id, "  AST analyzer not available (install javalang)")
            except Exception as e:
                add_scan_log(scan_id, f"  AST analysis error: {e}")
        scans[scan_id]["progress"] = 30

        # STEP 3: Reverse Engineering
        scans[scan_id]["current_step"] = "Reverse Engineering"
        add_scan_log(scan_id, "PHASE 3: Reverse Engineering")
        rev = ReverseEngineer(file_path)
        rev_results = rev.analyze()
        all_findings.extend(rev_results.get("findings", []))
        add_scan_log(scan_id, f"  Backend URLs: {len(rev_results.get('backend_urls', []))}")
        add_scan_log(scan_id, f"  Config Files: {len(rev_results.get('config_files', []))}")
        scans[scan_id]["progress"] = 40

        # STEP 4: Storage Security
        scans[scan_id]["current_step"] = "Storage Analysis"
        add_scan_log(scan_id, "PHASE 4: Storage Security Assessment")
        storage = StorageAnalyzer(file_path)
        storage_results = storage.analyze()
        all_findings.extend(storage_results.get("findings", []))
        add_scan_log(scan_id, f"  Storage issues: {len(storage_results.get('findings', []))}")
        scans[scan_id]["progress"] = 50

        # STEP 5: Network Security
        scans[scan_id]["current_step"] = "Network Analysis"
        add_scan_log(scan_id, "PHASE 5: Network Security Analysis")
        network = NetworkAnalyzer(file_path)
        network_results = network.analyze()
        all_findings.extend(network_results.get("findings", []))
        add_scan_log(scan_id, f"  Network issues: {len(network_results.get('findings', []))}")
        scans[scan_id]["progress"] = 60

        # STEP 6: API Security
        scans[scan_id]["current_step"] = "API Security Testing"
        add_scan_log(scan_id, "PHASE 6: API Security Testing")
        api_endpoints = static_results.get("api_endpoints", []) + rev_results.get("backend_urls", [])
        api = APISecurityTester(file_path, api_endpoints)
        api_results = api.analyze()
        all_findings.extend(api_results.get("findings", []))
        add_scan_log(scan_id, f"  API issues: {len(api_results.get('findings', []))}")
        scans[scan_id]["progress"] = 70

        # STEP 7: Dynamic Analysis (Frida + static heuristics)
        scans[scan_id]["current_step"] = "Dynamic Analysis"
        add_scan_log(scan_id, "PHASE 7: Dynamic Runtime Analysis")
        # Extract package name from manifest if available
        pkg_name = static_results.get("manifest", {}).get("package", file_path.stem)
        dynamic = DynamicAnalyzer(file_path, package_name=pkg_name)
        dynamic_results = dynamic.analyze()
        all_findings.extend(dynamic_results.get("findings", []))
        add_scan_log(scan_id, f"  Runtime indicators: {len(dynamic_results.get('findings', []))}")
        scans[scan_id]["progress"] = 80

        # STEP 8: Vulnerability Mapping
        scans[scan_id]["current_step"] = "Vulnerability Mapping"
        add_scan_log(scan_id, "PHASE 8: OWASP/CWE/CAPEC Vulnerability Mapping")
        mapper = VulnerabilityMapper()
        mapped = mapper.map_findings(all_findings)

        # Deduplicate before calling RAG enrichment (19x speedup by avoiding duplicate LLM completions)
        seen_titles = set()
        unique_mapped = []
        for f in mapped:
            if f.get("title") not in seen_titles:
                seen_titles.add(f["title"])
                unique_mapped.append(f)

        enriched = [rag.enrich_finding(f) for f in unique_mapped]
        add_scan_log(scan_id, f"  Unique vulnerabilities: {len(enriched)}")
        scans[scan_id]["progress"] = 85

        # STEP 9: Risk Assessment
        scans[scan_id]["current_step"] = "Risk Assessment"
        add_scan_log(scan_id, "PHASE 9: CVSS Risk Assessment")
        assessor = RiskAssessor()
        risk_results = assessor.assess(enriched)
        add_scan_log(scan_id, f"  Overall risk: {risk_results.get('overall_risk', 'unknown').upper()}")
        add_scan_log(scan_id, f"  Total findings: {risk_results.get('total_findings', 0)}")
        scans[scan_id]["progress"] = 90

        # STEP 10: Report Generation
        scans[scan_id]["current_step"] = "Report Generation"
        add_scan_log(scan_id, "PHASE 10: Generating Reports")

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

        gen = ReportGenerator(app_name, platform)
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
        add_scan_log(scan_id, f"COMPLETE: Analysis finished in {duration}s")
        add_scan_log(scan_id, f"Total unique findings: {risk_results['total_findings']}")

        save_scan_history()
        logger.info(f"[{scan_id}] Analysis complete in {duration}s. {risk_results['total_findings']} findings.")

    except Exception as e:
        logger.error(f"[{scan_id}] Analysis failed: {e}")
        scans[scan_id]["status"] = "failed"
        scans[scan_id]["error"] = str(e)
        scans[scan_id]["current_step"] = "Failed"
        add_scan_log(scan_id, f"ERROR: {str(e)}")
        scans[scan_id]["duration_seconds"] = round(time.time() - start_time, 2)
        save_scan_history()


@app.get("/api/scan/{scan_id}")
async def get_scan(scan_id: str):
    if scan_id not in scans:
        raise HTTPException(404, "Scan not found")
    return scans[scan_id]


@app.get("/api/scan/{scan_id}/log")
async def get_scan_log(scan_id: str):
    """Get real-time scan log."""
    if scan_id not in scans:
        raise HTTPException(404, "Scan not found")
    return {
        "scan_id": scan_id,
        "status": scans[scan_id]["status"],
        "progress": scans[scan_id]["progress"],
        "current_step": scans[scan_id].get("current_step", ""),
        "log": scans[scan_id].get("log", []),
    }


@app.get("/api/scan/{scan_id}/executive-summary")
async def get_executive_summary(scan_id: str):
    """Get a concise executive summary of the scan."""
    if scan_id not in scans:
        raise HTTPException(404, "Scan not found")
    s = scans[scan_id]
    if s["status"] != "completed":
        raise HTTPException(400, "Scan not completed")

    ra = s["results"]["risk_assessment"]
    app_info = s["results"]["application"]
    summary = ra.get("risk_summary", {})

    return {
        "application": app_info["name"],
        "platform": app_info["platform"],
        "overall_risk": ra["overall_risk"],
        "total_findings": ra["total_findings"],
        "critical": summary.get("critical", 0),
        "high": summary.get("high", 0),
        "medium": summary.get("medium", 0),
        "low": summary.get("low", 0),
        "info": summary.get("info", 0),
        "scan_duration": s.get("duration_seconds", 0),
        "scanned_at": s.get("completed_at", ""),
        "top_risks": [
            {"title": f["title"], "severity": f["severity"], "owasp": f.get("owasp", "")}
            for f in ra["findings"][:5]
        ],
    }


@app.get("/api/scan/{scan_id}/report/json")
async def get_json_report(scan_id: str):
    if scan_id not in scans:
        raise HTTPException(404, "Scan not found")
    scan = scans[scan_id]
    if scan["status"] != "completed":
        raise HTTPException(400, f"Scan status: {scan['status']}")
    report_path = scan["results"]["reports"]["json"]
    return FileResponse(report_path, media_type="application/json", filename=Path(report_path).name)


@app.get("/api/scan/{scan_id}/report/html")
async def get_html_report(scan_id: str):
    if scan_id not in scans:
        raise HTTPException(404, "Scan not found")
    scan = scans[scan_id]
    if scan["status"] != "completed":
        raise HTTPException(400, f"Scan status: {scan['status']}")
    report_path = scan["results"]["reports"]["html"]
    return FileResponse(report_path, media_type="text/html", filename=Path(report_path).name)


@app.get("/api/scans")
async def list_scans():
    return [{
        "id": s["id"],
        "filename": s["filename"],
        "status": s["status"],
        "progress": s["progress"],
        "platform": s["platform"],
        "current_step": s.get("current_step", ""),
        "started_at": s.get("started_at", ""),
        "completed_at": s.get("completed_at", ""),
        "duration_seconds": s.get("duration_seconds", 0),
        "total_findings": s.get("results", {}).get("risk_assessment", {}).get("total_findings", 0) if s.get("results") else 0,
        "overall_risk": s.get("results", {}).get("risk_assessment", {}).get("overall_risk", "pending") if s.get("results") else "pending",
    } for s in sorted(scans.values(), key=lambda x: x.get("started_at", ""), reverse=True)]


@app.delete("/api/scan/{scan_id}")
async def delete_scan(scan_id: str):
    """Delete a scan and its reports."""
    if scan_id not in scans:
        raise HTTPException(404, "Scan not found")
    del scans[scan_id]
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


if __name__ == "__main__":
    import uvicorn
    logger.info("[SHIELD] Mobile Security Agent v2.0 starting...")
    uvicorn.run("main:app", host=HOST, port=PORT, reload=DEBUG)
