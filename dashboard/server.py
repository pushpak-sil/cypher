"""
dashboard/server.py
FastAPI server powering the SYFER IPsec VPN Protocol Analyzer & Security Framework.
Provides API endpoints for PCAP upload, pre-captured run analysis, AI telemetry,
and report generation.
"""

import os
import sys
import json
import tempfile

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from fastapi import FastAPI, File, UploadFile, HTTPException
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from fastapi.middleware.cors import CORSMiddleware
from scapy.all import rdpcap
from scripts.parse_pcap import get_esp_packets
from core.dissector import analyze_pcap
from core.classifier import classify_esp_traffic
from core.security_engine import evaluate_security_posture
from core.report_generator import generate_executive_report_html, generate_technical_report_html

STATIC_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "static")
MANIFEST_PATH = os.path.join(PROJECT_ROOT, "manifest.json")
METRICS_PATH = os.path.join(PROJECT_ROOT, "models", "metrics.json")
CAPTURES_DIR = os.path.join(PROJECT_ROOT, "captures")

app = FastAPI(
    title="SYFER - IPsec Protocol Analyzer",
    description="AI-Powered IPsec VPN Protocol Analyzer and Automated Security Assessment Framework",
    version="2.0.0"
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


_ANALYSIS_CACHE = {}


def run_full_pipeline(pcap_path: str, pcap_name: str) -> dict:
    """Runs dissection, AI encrypted traffic classification, and security audit on a PCAP."""
    # Return from cache if already processed to eliminate redundant parsing delay
    cache_key = os.path.basename(pcap_path)
    if cache_key in _ANALYSIS_CACHE:
        return _ANALYSIS_CACHE[cache_key]

    # 1. Dissect protocols and IKE/ESP
    dissection = analyze_pcap(pcap_path)
    if "error" in dissection:
        return dissection

    dissection["pcap_name"] = pcap_name

    # 2. Extract ESP packets for AI traffic classification
    try:
        pkts = rdpcap(pcap_path)
        esp_pkts = get_esp_packets(pkts)
        ai_res = classify_esp_traffic(esp_pkts)
    except Exception as e:
        ai_res = {
            "predicted_traffic": "Error",
            "confidence": 0.0,
            "confidence_percentage": 0.0,
            "error": str(e)
        }
    dissection["ai_inference"] = ai_res

    # 3. Automated Security Assessment & Compliance Audit
    sec_res = evaluate_security_posture(
        dissection.get("crypto_parameters", {}),
        dissection.get("esp_analysis", {})
    )
    dissection["security"] = sec_res

    # Cache results
    _ANALYSIS_CACHE[cache_key] = dissection
    _ANALYSIS_CACHE["latest"] = dissection
    return dissection



@app.get("/api/runs")
def get_runs():
    """Returns list of pre-captured runs available in the testbed."""
    if not os.path.exists(MANIFEST_PATH):
        return []
    with open(MANIFEST_PATH, "r") as f:
        manifest = json.load(f)
    return manifest


@app.get("/api/run/{run_id}")
def analyze_run(run_id: str):
    """Analyzes a specific pre-captured run from the testbed."""
    pcap_path = os.path.join(CAPTURES_DIR, f"{run_id}.pcap")
    if not os.path.exists(pcap_path):
        raise HTTPException(status_code=404, detail=f"Capture file {run_id}.pcap not found on disk.")
    return run_full_pipeline(pcap_path, f"{run_id}.pcap")


@app.post("/api/analyze-pcap")
async def upload_and_analyze(file: UploadFile = File(...)):
    """Accepts uploaded PCAP or PCAPNG file and runs real-time analysis."""
    suffix = os.path.splitext(file.filename)[1] or ".pcap"
    with tempfile.NamedTemporaryFile(delete=False, suffix=suffix) as tmp:
        content = await file.read()
        tmp.write(content)
        tmp_path = tmp.name

    try:
        result = run_full_pipeline(tmp_path, file.filename)
        return result
    finally:
        if os.path.exists(tmp_path):
            try:
                os.remove(tmp_path)
            except Exception:
                pass


@app.get("/api/model-telemetry")
def get_model_telemetry():
    """Returns AI model performance metrics, confusion matrix, and feature importances."""
    if not os.path.exists(METRICS_PATH):
        raise HTTPException(status_code=404, detail="Model metrics not found. Run scripts/train_model.py first.")
    with open(METRICS_PATH, "r") as f:
        metrics = json.load(f)
    return metrics


@app.get("/api/report/{run_id}/{report_type}", response_class=HTMLResponse)
def export_report(run_id: str, report_type: str):
    """Generates standalone printable HTML report (executive or technical)."""
    data = None
    if run_id in ("latest", "current"):
        data = _ANALYSIS_CACHE.get("latest")
    elif f"{run_id}.pcap" in _ANALYSIS_CACHE:
        data = _ANALYSIS_CACHE[f"{run_id}.pcap"]
    elif run_id in _ANALYSIS_CACHE:
        data = _ANALYSIS_CACHE[run_id]

    if not data:
        pcap_path = os.path.join(CAPTURES_DIR, f"{run_id}.pcap")
        if not os.path.exists(pcap_path):
            raise HTTPException(status_code=404, detail=f"Capture file {run_id}.pcap not found.")
        data = run_full_pipeline(pcap_path, f"{run_id}.pcap")

    if report_type.lower() == "executive":
        return HTMLResponse(content=generate_executive_report_html(data))
    elif report_type.lower() == "technical":
        return HTMLResponse(content=generate_technical_report_html(data))
    else:
        raise HTTPException(status_code=400, detail="Invalid report type. Choose 'executive' or 'technical'.")



# Mount static assets for the web UI
os.makedirs(STATIC_DIR, exist_ok=True)
app.mount("/", StaticFiles(directory=STATIC_DIR, html=True), name="static")

if __name__ == "__main__":
    import uvicorn
    print("[+] Starting SYFER IPsec Protocol Analyzer Dashboard on http://127.0.0.1:8000")
    uvicorn.run("dashboard.server:app", host="127.0.0.1", port=8000, reload=True)
