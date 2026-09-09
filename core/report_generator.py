"""
core/report_generator.py
Generates professional, printable Executive and Technical Assessment Reports
in self-contained HTML format with enterprise styling.
"""

from typing import Dict, Any


def generate_executive_report_html(data: Dict[str, Any]) -> str:
    """
    Generates a high-level Executive Security Briefing for C-suite / SOC Directors.
    """
    summary = data.get("summary", {})
    crypto = data.get("crypto_parameters", {})
    sec = data.get("security", {})
    ai = data.get("ai_inference", {})
    pcap_name = data.get("pcap_name", "Network Capture")

    score = sec.get("security_score", 0)
    posture = sec.get("posture", "Unknown")
    posture_color = sec.get("posture_color", "#06b6d4")
    threats = sec.get("threat_matrix", [])
    compliance = sec.get("compliance", {})

    ike_version = crypto.get("ike_version", "Unknown")
    mode_raw = str(crypto.get("mode", "Not Observed"))
    mode_disp = mode_raw.capitalize() if mode_raw.lower() in ("tunnel", "transport") else mode_raw

    threat_rows = ""
    for t in threats:
        sev = t.get("severity", "MEDIUM")
        sev_color = "#f43f5e" if sev == "CRITICAL" else "#ea580c" if sev == "HIGH" else "#f59e0b"
        threat_rows += f"""
        <tr>
            <td style="padding:10px; border-bottom:1px solid #334155; font-weight:600;">{t.get('title')}</td>
            <td style="padding:10px; border-bottom:1px solid #334155;"><span style="background:{sev_color}; color:#fff; padding:3px 8px; border-radius:4px; font-size:11px; font-weight:700;">{sev}</span></td>
            <td style="padding:10px; border-bottom:1px solid #334155; color:#94a3b8;">{t.get('cve')}</td>
            <td style="padding:10px; border-bottom:1px solid #334155; color:#cbd5e1;">{t.get('impact')}</td>
        </tr>
        """

    if not threat_rows:
        threat_rows = "<tr><td colspan='4' style='padding:15px; text-align:center; color:#10b981;'>No critical vulnerabilities identified. Configuration conforms to baseline security standards.</td></tr>"

    # Findings-driven strategic recommendation. Previously this was static boilerplate
    # that told every reader to decommission IKEv1 and enable PFS -- even on a clean
    # IKEv2/AES-256 tunnel -- contradicting the assessment. Build it from real threats.
    threat_ids = {t.get("id") for t in threats}
    _rec_map = [
        ("THREAT-IKEV1", "migrate remaining IKEv1 gateways to IKEv2"),
        ("THREAT-SWEET32", "replace 64-bit block ciphers (3DES/DES) with AES-256-GCM"),
        ("THREAT-NULL-CIPHER", "mandate AES-256-GCM encryption (NULL cipher provides zero confidentiality)"),
        ("THREAT-MD5-BROKEN", "replace MD5 integrity with HMAC-SHA-256 or an AEAD cipher"),
        ("THREAT-SHA1-WEAK", "upgrade SHA-1 integrity to SHA-256"),
        ("THREAT-LOGJAM-DH", "eliminate Diffie-Hellman groups below 2048 bits (use Group 14/19/31)"),
        ("THREAT-NO-PFS", "enable Perfect Forward Secrecy on Phase-2 / Child SA proposals"),
        ("THREAT-REPLAY-ANOMALY", "verify the anti-replay window and enable Extended Sequence Numbers (ESN)"),
    ]
    recs = [text for tid, text in _rec_map if tid in threat_ids]
    if recs:
        rec_text = "Priority remediation &mdash; " + "; ".join(recs) + "."
    else:
        rec_text = (
            f"The observable IKE (phase-1) parameters conform to current best practice (score {score}/100). "
            "Maintain this baseline with regular re-keying. Note that the encapsulation mode, the ESP data "
            "cipher, and Perfect Forward Secrecy are negotiated in the encrypted phase-2 exchange and cannot "
            "be confirmed from a passive capture &mdash; validate them directly against the VPN gateway configuration."
        )

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>IPsec Security Assessment - Executive Report</title>
    <style>
        body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif; background:#0b0f19; color:#f8fafc; margin:0; padding:0 0 60px; }}
        .report-nav-bar {{ position: sticky; top:0; z-index:100; background:rgba(15,23,42,0.95); backdrop-filter:blur(10px); border-bottom:1px solid #334155; padding:12px 30px; display:flex; justify-content:space-between; align-items:center; }}
        .nav-btn {{ display:inline-flex; align-items:center; gap:6px; padding:8px 16px; border-radius:6px; font-size:13px; font-weight:600; cursor:pointer; text-decoration:none; border:none; transition:all 0.2s; }}
        .btn-back {{ background:#1e293b; color:#06b6d4; border:1px solid #06b6d4; }}
        .btn-back:hover {{ background:#06b6d4; color:#000; }}
        .btn-print {{ background:linear-gradient(135deg, #06b6d4, #0284c7); color:#fff; }}
        .btn-print:hover {{ opacity:0.9; }}
        .container {{ max-width: 900px; margin: 30px auto 0; background:#1e293b; border-radius:12px; padding:35px; box-shadow: 0 20px 25px -5px rgba(0, 0, 0, 0.5); border:1px solid #334155; }}
        .header {{ display: flex; justify-content: space-between; align-items: flex-start; border-bottom: 2px solid #334155; padding-bottom: 20px; }}
        .badge {{ background: {posture_color}; color: #fff; padding: 6px 14px; border-radius: 20px; font-size: 13px; font-weight: 700; display: inline-block; }}
        .score-card {{ background: #0f172a; border-radius: 10px; padding: 20px; text-align: center; border: 1px solid #334155; min-width: 140px; }}
        .score-num {{ font-size: 44px; font-weight: 800; color: {posture_color}; }}
        .grid {{ display: grid; grid-template-columns: repeat(3, 1fr); gap: 15px; margin: 25px 0; }}
        .kpi {{ background: #0f172a; padding: 15px; border-radius: 8px; border: 1px solid #334155; }}
        .kpi-title {{ font-size: 11px; text-transform: uppercase; color: #94a3b8; letter-spacing: 0.05em; margin-bottom: 5px; }}
        .kpi-value {{ font-size: 16px; font-weight: 700; color: #f1f5f9; }}
        table {{ width: 100%; border-collapse: collapse; margin-top: 15px; font-size: 13px; }}
        th {{ text-align: left; padding: 10px; background: #0f172a; color: #94a3b8; font-size: 11px; text-transform: uppercase; border-bottom: 2px solid #334155; }}
        .actions-box {{ background: rgba(6, 182, 212, 0.08); border-left: 4px solid #06b6d4; padding: 15px; border-radius: 4px; margin-top: 25px; }}
        @media print {{
            .report-nav-bar {{ display: none !important; }}
            body {{ background: #fff; color: #000; padding:0; }}
            .container {{ border: none; box-shadow: none; margin:0; max-width:100%; }}
        }}
    </style>
</head>
<body>
    <div class="report-nav-bar">
        <button class="nav-btn btn-back" onclick="window.history.length > 1 ? window.history.back() : (window.location.href='/')">
            &larr; Back to Dashboard
        </button>
        <div style="font-size:13px; font-weight:700; color:#94a3b8; letter-spacing:0.05em;">SYFER // EXECUTIVE REPORT BRIEFING</div>
        <button class="nav-btn btn-print" onclick="window.print()">
            &#128438; Print / Save PDF
        </button>
    </div>
    <div class="container">
        <div class="header">
            <div>
                <h1 style="margin:0 0 8px 0; font-size:24px; color:#f8fafc;">IPsec VPN Security Assessment</h1>
                <p style="margin:0; color:#94a3b8; font-size:14px;">Target Trace: <strong>{pcap_name}</strong> | Automated Audit Framework</p>
                <div style="margin-top:12px;"><span class="badge">{posture}</span></div>
            </div>
            <div class="score-card">
                <div style="font-size:11px; text-transform:uppercase; color:#94a3b8; font-weight:700;">Security Score</div>
                <div class="score-num">{score}</div>
                <div style="font-size:11px; color:#64748b;">Out of 100</div>
            </div>
        </div>

        <div class="grid">
            <div class="kpi">
                <div class="kpi-title">Protocol & Encap Mode</div>
                <div class="kpi-value">{ike_version}</div>
                <div style="font-size:11.5px; margin-top:4px; color:#94a3b8;">Encap Mode: {mode_disp}</div>
            </div>
            <div class="kpi">
                <div class="kpi-title">IKE Cipher (Phase-1)</div>
                <div class="kpi-value">{crypto.get('cipher')}</div>
            </div>
            <div class="kpi">
                <div class="kpi-title">AI Traffic & Anomaly Assessment</div>
                <div class="kpi-value" style="color:#10b981;">{ai.get('predicted_traffic', 'Unknown').upper()} ({ai.get('confidence_percentage', 0)}% conf)</div>
                <div style="font-size:11.5px; margin-top:5px; font-weight:600; color:{'#f43f5e' if ai.get('is_anomaly') else '#10b981'};">Anomaly Risk: {ai.get('anomaly_score', 0)}% [{ai.get('anomaly_status', 'NORMAL')}]</div>
            </div>
        </div>

        <h3 style="margin-top:30px; font-size:16px; border-bottom:1px solid #334155; padding-bottom:8px;">Compliance Benchmark Status</h3>
        <div style="display:flex; gap:12px; margin: 15px 0;">
            <div style="flex:1; padding:12px; background:#0f172a; border-radius:6px; border:1px solid #334155;">
                <div style="font-size:12px; font-weight:700;">NIST SP 800-77 Rev. 1</div>
                <div style="font-size:14px; font-weight:800; color:{'#10b981' if compliance.get('nist_sp_800_77_r1', {}).get('compliant') else '#f43f5e'};">
                    {compliance.get('nist_sp_800_77_r1', {}).get('status', 'N/A')}
                </div>
            </div>
            <div style="flex:1; padding:12px; background:#0f172a; border-radius:6px; border:1px solid #334155;">
                <div style="font-size:12px; font-weight:700;">NSA CNSA Suite</div>
                <div style="font-size:14px; font-weight:800; color:{'#10b981' if compliance.get('nsa_cnsa_suite', {}).get('compliant') else '#f43f5e'};">
                    {compliance.get('nsa_cnsa_suite', {}).get('status', 'N/A')}
                </div>
            </div>
            <div style="flex:1; padding:12px; background:#0f172a; border-radius:6px; border:1px solid #334155;">
                <div style="font-size:12px; font-weight:700;">RFC 8221 (ESP Algorithms)</div>
                <div style="font-size:14px; font-weight:800; color:{'#10b981' if compliance.get('rfc_8221', {}).get('compliant') else '#f43f5e'};">
                    {compliance.get('rfc_8221', {}).get('status', 'N/A')}
                </div>
            </div>
        </div>

        <h3 style="margin-top:30px; font-size:16px; border-bottom:1px solid #334155; padding-bottom:8px;">Identified Threat Matrix</h3>
        <table>
            <thead>
                <tr>
                    <th>Vulnerability</th>
                    <th>Severity</th>
                    <th>Standard / CVE</th>
                    <th>Business Impact</th>
                </tr>
            </thead>
            <tbody>
                {threat_rows}
            </tbody>
        </table>

        <div class="actions-box">
            <h4 style="margin:0 0 6px 0; color:#38bdf8;">Strategic Security Recommendation</h4>
            <p style="margin:0; font-size:13px; line-height:1.5; color:#cbd5e1;">
                {rec_text}
            </p>
        </div>
    </div>
</body>
</html>
"""
    return html


def generate_technical_report_html(data: Dict[str, Any]) -> str:
    """
    Generates an in-depth Technical Protocol Audit Report with full packet breakdown,
    IKE transforms, ESP flow metrics, and configuration hardening snippets.
    """
    summary = data.get("summary", {})
    crypto = data.get("crypto_parameters", {})
    sec = data.get("security", {})
    ai = data.get("ai_inference", {})
    esp = data.get("esp_analysis", {})
    ike_handshake = data.get("ike_handshake", [])
    remediations = sec.get("remediations", {})
    informational = sec.get("informational", [])

    cipher_val = str(crypto.get("cipher", "Unknown"))

    def _integrity_eval(algo):
        a = str(algo).upper()
        if "MD5" in a:
            return "Broken -- practical collision attacks (non-compliant)"
        if "SHA1" in a or "SHA-1" in a:
            return "Deprecated SHA-1 (SLOTH) -- upgrade advised"
        if "384" in a or "512" in a:
            return "Strong SHA-2 -- CNSA-grade"
        if "256" in a or "SHA2" in a:
            return "SHA-256 -- Standard Compliant"
        if "GCM" in cipher_val.upper():
            return "AEAD-integrated integrity (GCM)"
        return "Not identified from capture"

    pfs_status = crypto.get("pfs_status", "Enabled" if crypto.get("pfs_enabled") else "Not Observed")
    pfs_wire = {
        "Enabled": "Enabled (fresh DH in CHILD_SA)",
        "Disabled": "Disabled (rekey without fresh DH)",
    }.get(pfs_status, "Not Observed (no rekey captured)")
    pfs_eval = {
        "Enabled": "Protects past sessions",
        "Disabled": "High compromise exposure",
    }.get(pfs_status, "Not determinable from passive capture")

    mode_raw = str(crypto.get("mode", "Not Observed"))
    mode_disp = mode_raw.capitalize() if mode_raw.lower() in ("tunnel", "transport") else mode_raw
    mode_eval = ("Inner IP headers encrypted" if mode_raw.lower() == "tunnel"
                 else "Only payload encrypted" if mode_raw.lower() == "transport"
                 else "Negotiated in encrypted phase-2 -- not observable passively")
    esp_cipher = crypto.get("esp_cipher", "Not Observed")

    # Observability caveats box: honestly document which parameters cannot be
    # read from a passive capture. Empty -> box omitted.
    if informational:
        _items = "".join(
            f"<li style='margin-bottom:6px;'><strong style='color:#cbd5e1;'>{n.get('title','Note')}:</strong> "
            f"<span style='color:#94a3b8;'>{n.get('detail','')}</span></li>"
            for n in informational
        )
        caveats_html = f"""
        <div style="background:rgba(245,158,11,0.06); border-left:4px solid #f59e0b; padding:14px 16px; border-radius:4px; margin-top:14px;">
            <div style="font-size:12px; font-weight:700; color:#f59e0b; text-transform:uppercase; letter-spacing:0.05em;">Observability &amp; Assessment Caveats</div>
            <ul style="margin:8px 0 0 0; padding-left:18px; font-size:12px; line-height:1.5;">{_items}</ul>
        </div>
        """
    else:
        caveats_html = ""

    ike_rows = ""
    for m in ike_handshake:
        init_str = "Initiator -> Responder" if m.get("is_initiator") else "Responder -> Initiator"
        p_names = ", ".join([p.get("name", "") for p in m.get("payloads", [])])
        ike_rows += f"""
        <tr>
            <td style="padding:8px; border-bottom:1px solid #334155;">{m.get('timestamp', 0):.4f}</td>
            <td style="padding:8px; border-bottom:1px solid #334155; font-family:monospace;">{m.get('src')} &rarr; {m.get('dst')}</td>
            <td style="padding:8px; border-bottom:1px solid #334155;"><strong>{m.get('exchange_type')}</strong></td>
            <td style="padding:8px; border-bottom:1px solid #334155; font-family:monospace; font-size:11px;">Init SPI: {m.get('initiator_spi', '')[:8]}...</td>
            <td style="padding:8px; border-bottom:1px solid #334155; font-size:12px; color:#94a3b8;">{p_names}</td>
        </tr>
        """

    if not ike_rows:
        ike_rows = "<tr><td colspan='5' style='padding:12px; text-align:center; color:#94a3b8;'>No IKE negotiation packets present in this trace.</td></tr>"

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>IPsec Protocol Audit - Technical Report</title>
    <style>
        body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, monospace; background:#0b0f19; color:#f8fafc; margin:0; padding:0 0 60px; }}
        .report-nav-bar {{ position: sticky; top:0; z-index:100; background:rgba(15,23,42,0.95); backdrop-filter:blur(10px); border-bottom:1px solid #334155; padding:12px 30px; display:flex; justify-content:space-between; align-items:center; }}
        .nav-btn {{ display:inline-flex; align-items:center; gap:6px; padding:8px 16px; border-radius:6px; font-size:13px; font-weight:600; cursor:pointer; text-decoration:none; border:none; transition:all 0.2s; }}
        .btn-back {{ background:#1e293b; color:#06b6d4; border:1px solid #06b6d4; }}
        .btn-back:hover {{ background:#06b6d4; color:#000; }}
        .btn-print {{ background:linear-gradient(135deg, #06b6d4, #0284c7); color:#fff; }}
        .btn-print:hover {{ opacity:0.9; }}
        .container {{ max-width: 1000px; margin: 30px auto 0; background:#1e293b; border-radius:12px; padding:35px; border:1px solid #334155; box-shadow: 0 20px 25px -5px rgba(0, 0, 0, 0.5); }}
        table {{ width: 100%; border-collapse: collapse; margin-top: 10px; font-size: 12px; }}
        th {{ text-align: left; padding: 10px; background: #0f172a; color: #94a3b8; font-size: 11px; text-transform: uppercase; border-bottom: 2px solid #334155; }}
        pre {{ background:#0f172a; padding:15px; border-radius:6px; border:1px solid #334155; font-size:12px; color:#38bdf8; overflow-x:auto; }}
        .section-title {{ font-size:16px; font-weight:700; color:#f1f5f9; border-bottom:1px solid #334155; padding-bottom:6px; margin-top:30px; }}
        .grid-2 {{ display: grid; grid-template-columns: 1fr 1fr; gap: 20px; }}
        @media print {{
            .report-nav-bar {{ display: none !important; }}
            body {{ background: #fff; color: #000; padding:0; }}
            .container {{ border: none; box-shadow: none; margin:0; max-width:100%; }}
            pre {{ background: #f1f5f9; color: #000; border-color: #cbd5e1; }}
        }}
    </style>
</head>
<body>
    <div class="report-nav-bar">
        <button class="nav-btn btn-back" onclick="window.history.length > 1 ? window.history.back() : (window.location.href='/')">
            &larr; Back to Dashboard
        </button>
        <div style="font-size:13px; font-weight:700; color:#94a3b8; letter-spacing:0.05em;">SYFER // TECHNICAL AUDIT REPORT</div>
        <button class="nav-btn btn-print" onclick="window.print()">
            &#128438; Print / Save PDF
        </button>
    </div>
    <div class="container">
        <h1 style="margin:0 0 5px 0; font-size:22px;">IPsec Protocol Technical Audit & Packet Analysis</h1>
        <p style="color:#94a3b8; font-size:13px; margin:0 0 25px 0;">Automated Deep Packet Dissection, Cryptographic Assessment & ML Inference</p>

        <div class="section-title">1. Dissected Security Association Parameters</div>
        <p style="font-size:11.5px; color:#94a3b8; margin:8px 0 0 0;">Values are derived from the observable (cleartext) IKE phase-1 exchange. Parameters negotiated inside the encrypted phase-2 exchange are reported as <em>Not Observed</em> rather than assumed.</p>
        <table>
            <tr><th style="width:250px;">Parameter</th><th>Negotiated Wire Value</th><th>Cryptographic Evaluation</th></tr>
            <tr><td style="padding:8px; border-bottom:1px solid #334155;">IKE Version</td><td style="padding:8px; border-bottom:1px solid #334155;">{crypto.get('ike_version')}</td><td style="padding:8px; border-bottom:1px solid #334155;">{'Modern RFC 7296' if 'IKEv2' in crypto.get('ike_version', '') else 'Deprecated (vulnerable to dictionary attack)'}</td></tr>
            <tr><td style="padding:8px; border-bottom:1px solid #334155;">IKE (Phase-1) Cipher</td><td style="padding:8px; border-bottom:1px solid #334155;">{cipher_val}</td><td style="padding:8px; border-bottom:1px solid #334155;">{'Authenticated Encryption (AEAD)' if 'GCM' in cipher_val.upper() else 'CBC Mode (requires HMAC)'}</td></tr>
            <tr><td style="padding:8px; border-bottom:1px solid #334155;">ESP Data Cipher</td><td style="padding:8px; border-bottom:1px solid #334155; color:#94a3b8;">{esp_cipher}</td><td style="padding:8px; border-bottom:1px solid #334155; color:#94a3b8;">Negotiated in encrypted CHILD_SA -- not observable from a passive capture</td></tr>
            <tr><td style="padding:8px; border-bottom:1px solid #334155;">IKE (Phase-1) Integrity</td><td style="padding:8px; border-bottom:1px solid #334155;">{crypto.get('auth_algo')}</td><td style="padding:8px; border-bottom:1px solid #334155;">{_integrity_eval(crypto.get('auth_algo'))}</td></tr>
            <tr><td style="padding:8px; border-bottom:1px solid #334155;">Diffie-Hellman Group</td><td style="padding:8px; border-bottom:1px solid #334155;">{crypto.get('dh_group')}</td><td style="padding:8px; border-bottom:1px solid #334155;">Group ID {crypto.get('dh_group_id', 'N/A')}</td></tr>
            <tr><td style="padding:8px; border-bottom:1px solid #334155;">Perfect Forward Secrecy</td><td style="padding:8px; border-bottom:1px solid #334155;">{pfs_wire}</td><td style="padding:8px; border-bottom:1px solid #334155;">{pfs_eval}</td></tr>
            <tr><td style="padding:8px; border-bottom:1px solid #334155;">Encapsulation Mode</td><td style="padding:8px; border-bottom:1px solid #334155;">{mode_disp}</td><td style="padding:8px; border-bottom:1px solid #334155;">{mode_eval}</td></tr>
        </table>
        {caveats_html}

        <div class="section-title">2. IKE Negotiation Message Sequence</div>
        <table>
            <thead>
                <tr>
                    <th>Timestamp</th>
                    <th>Flow (Src &rarr; Dst)</th>
                    <th>Exchange Type</th>
                    <th>Security Context</th>
                    <th>Payload Chain</th>
                </tr>
            </thead>
            <tbody>
                {ike_rows}
            </tbody>
        </table>

        <div class="section-title">3. ESP Sequence & Anti-Replay Protection</div>
        <div class="grid-2" style="margin-top:10px;">
            <div style="background:#0f172a; padding:15px; border-radius:6px; border:1px solid #334155;">
                <div style="font-size:11px; color:#94a3b8; text-transform:uppercase;">Observed SPIs</div>
                <div style="font-size:13px; font-family:monospace; margin-top:4px;">{', '.join(esp.get('unique_spis', ['None']))}</div>
            </div>
            <div style="background:#0f172a; padding:15px; border-radius:6px; border:1px solid #334155;">
                <div style="font-size:11px; color:#94a3b8; text-transform:uppercase;">Sequence Monotonicity</div>
                <div style="font-size:13px; margin-top:4px; color:{'#10b981' if esp.get('replay_window_ok') else '#f43f5e'};">
                    {'VALID - No Duplicate Sequences' if esp.get('replay_window_ok') else 'ANOMALOUS - Duplicate Sequences Detected'}
                </div>
            </div>
        </div>

        <div class="section-title">4. AI Encrypted Traffic Classification & Anomaly Detection</div>
        <div style="background:#0f172a; padding:15px; border-radius:6px; border:1px solid #334155; margin-top:10px;">
            <div style="display:flex; justify-content:space-between; margin-bottom:10px;">
                <div>
                    <span style="color:#94a3b8; font-size:11px; text-transform:uppercase;">Predicted Application</span>
                    <div style="font-size:18px; font-weight:800; color:#38bdf8;">{ai.get('predicted_traffic', 'Unknown').upper()} ({ai.get('confidence_percentage', 0)}% Confidence)</div>
                </div>
                <div>
                    <span style="color:#94a3b8; font-size:11px; text-transform:uppercase;">Anomaly Engine Status</span>
                    <div style="font-size:18px; font-weight:800; color:{'#f43f5e' if ai.get('is_anomaly') else '#10b981'};">{ai.get('anomaly_status', 'NORMAL')} (Risk Score: {ai.get('anomaly_score', 0)}%)</div>
                </div>
            </div>
            <p style="font-size:12.5px; color:#cbd5e1; margin:0 0 8px 0;"><strong>Diagnostic Verdict:</strong> {ai.get('anomaly_verdict', 'Normal baseline traffic')}</p>
            <p style="font-size:12px; color:#94a3b8; margin:0;">Inference Pipeline Latency: <strong>{ai.get('latency_ms', 1.8)} ms</strong> | Flow Profile Extracted Across ESP Window</p>
        </div>

        <div class="section-title">5. Hardened Configuration Remediation</div>
        <h4 style="margin:15px 0 5px 0; color:#38bdf8;">strongSwan Configuration Template (/etc/ipsec.conf)</h4>
        <pre>{remediations.get('strongswan')}</pre>

        <h4 style="margin:15px 0 5px 0; color:#38bdf8;">Cisco IOS / ASA Template</h4>
        <pre>{remediations.get('cisco')}</pre>
    </div>
</body>
</html>
"""
    return html
