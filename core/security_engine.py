"""
core/security_engine.py
Automated Security Assessment & Threat Matrix Engine for IPsec VPN.
Evaluates cryptographic configurations against NIST SP 800-77 Rev. 1,
NSA CNSA Suite, and RFC 8221, calculates an enterprise 0-100 Security Score,
builds the Threat Matrix, and generates actionable configuration remediations.
"""

from typing import Dict, List, Any


def evaluate_security_posture(crypto_params: Dict[str, Any], esp_analysis: Dict[str, Any] = None) -> Dict[str, Any]:
    """
    Performs comprehensive audit of IPsec parameters and returns:
    - Overall Security Score (0 - 100)
    - Posture Classification
    - Compliance Checklists (NIST SP 800-77r1, NSA CNSA, RFC 8221)
    - Enterprise Threat Matrix (Vulnerability, CVE, Severity, Impact, Remediation)
    - Config Hardening Snippets (strongSwan, Cisco, pfSense)
    """
    esp_analysis = esp_analysis or {}
    ike_version = crypto_params.get("ike_version", "Unknown")
    cipher = crypto_params.get("cipher", "Unknown").upper()
    auth_algo = crypto_params.get("auth_algo", "Unknown").upper()
    dh_group = crypto_params.get("dh_group", "Unknown")
    dh_id = crypto_params.get("dh_group_id")
    # PFS is tri-state: "Enabled" / "Disabled" / "Not Observed". Fall back to the
    # legacy boolean only if the newer status field is absent.
    pfs_status = crypto_params.get("pfs_status")
    if pfs_status is None:
        pfs_status = "Enabled" if crypto_params.get("pfs_enabled", False) else "Disabled"
    mode = crypto_params.get("mode", "tunnel").lower()
    keylife = crypto_params.get("key_lifetime", "Standard (8h)")

    score = 100
    deductions = []
    informational: List[Dict[str, Any]] = []
    threats: List[Dict[str, Any]] = []

    # -------------------------------------------------------------
    # 1. Protocol / IKE Version Assessment
    # -------------------------------------------------------------
    is_ikev1 = "IKEV1" in ike_version.upper()
    if is_ikev1:
        score -= 20
        deductions.append({"component": "Protocol", "points": 20, "reason": "Deprecated IKEv1 protocol in use"})
        threats.append({
            "id": "THREAT-IKEV1",
            "title": "Use of Deprecated IKEv1 Protocol",
            "cve": "RFC 7296 Deprecation",
            "severity": "HIGH",
            "cvss": 7.5,
            "likelihood": "High",
            "impact": "Exposes identity payloads in cleartext during Main/Aggressive Mode; susceptible to offline dictionary attacks on PSK and amplification attacks.",
            "recommendation": "Migrate immediately to IKEv2 (RFC 7296) with authenticated identity encryption.",
        })

    # -------------------------------------------------------------
    # 2. Cipher Suite Assessment
    # -------------------------------------------------------------
    if "3DES" in cipher or "DES" in cipher:
        score -= 35
        deductions.append({"component": "Cipher", "points": 35, "reason": "Vulnerable 64-bit block cipher (Sweet32)"})
        threats.append({
            "id": "THREAT-SWEET32",
            "title": "Sweet32 Vulnerability in 64-bit Block Cipher (3DES/DES)",
            "cve": "CVE-2016-2183",
            "severity": "CRITICAL",
            "cvss": 9.1,
            "likelihood": "Medium",
            "impact": "Collisions in 64-bit block ciphers allow plaintext recovery of session tokens and cookies after ~32GB of encrypted traffic.",
            "recommendation": "Replace 3DES/DES with AES-256-GCM or AES-256-CBC.",
        })
    elif "128" in cipher and "CBC" in cipher:
        score -= 5
        deductions.append({"component": "Cipher", "points": 5, "reason": "AES-128-CBC is legacy; AEAD (AES-GCM) preferred"})
    elif "NULL" in cipher:
        score -= 50
        deductions.append({"component": "Cipher", "points": 50, "reason": "NULL encryption: traffic is completely plaintext!"})
        threats.append({
            "id": "THREAT-NULL-CIPHER",
            "title": "Null Encryption Configured",
            "cve": "CWE-311",
            "severity": "CRITICAL",
            "cvss": 10.0,
            "likelihood": "High",
            "impact": "Zero confidentiality; payload is transmitted in cleartext.",
            "recommendation": "Mandate AES-256-GCM encryption in ESP proposal.",
        })

    # -------------------------------------------------------------
    # 3. Integrity / Hash Assessment
    # -------------------------------------------------------------
    if "MD5" in auth_algo:
        score -= 25
        deductions.append({"component": "Hash/Auth", "points": 25, "reason": "Cryptographically broken MD5 hash"})
        threats.append({
            "id": "THREAT-MD5-BROKEN",
            "title": "Broken MD5 Hash Algorithm in IPsec Proposal",
            "cve": "RFC 6151 / CWE-327",
            "severity": "HIGH",
            "cvss": 7.8,
            "likelihood": "Medium",
            "impact": "MD5 suffers practical collision attacks; provides inadequate message integrity for modern threat models.",
            "recommendation": "Upgrade to HMAC-SHA-256 or use AEAD cipher (AES-GCM).",
        })
    elif "SHA1" in auth_algo:
        score -= 15
        deductions.append({"component": "Hash/Auth", "points": 15, "reason": "Weakened SHA-1 hash algorithm"})
        threats.append({
            "id": "THREAT-SHA1-WEAK",
            "title": "Weak SHA-1 Hash Algorithm (SLOTH Vulnerability)",
            "cve": "RFC 6194 / CVE-2015-7575",
            "severity": "MEDIUM",
            "cvss": 6.2,
            "likelihood": "Medium",
            "impact": "Theoretical collision attacks exist (SHAttered attack). NIST SP 800-131A disallows SHA-1 for digital signatures and integrity.",
            "recommendation": "Upgrade to SHA-256 (SHA2) or use authenticated encryption (GCM).",
        })

    # -------------------------------------------------------------
    # 4. Diffie-Hellman Key Exchange Assessment
    # -------------------------------------------------------------
    # Check for weak DH groups: Group 1 (768-bit), Group 2 (1024-bit), Group 5 (1536-bit)
    if dh_id in (1, 2, 5) or "MODP1024" in dh_group.upper() or "MODP768" in dh_group.upper() or "MODP1536" in dh_group.upper():
        score -= 20
        deductions.append({"component": "Key Exchange", "points": 20, "reason": "Diffie-Hellman Group < 14 (Logjam attack susceptibility)"})
        threats.append({
            "id": "THREAT-LOGJAM-DH",
            "title": "Weak Diffie-Hellman Group (< 2048-bit MODP)",
            "cve": "CVE-2015-4000 (Logjam)",
            "severity": "HIGH",
            "cvss": 7.4,
            "likelihood": "Medium",
            "impact": "1024-bit primes can be precomputed by sophisticated adversaries (Number Field Sieve), allowing passive decryption of VPN tunnels.",
            "recommendation": "Enforce DH Group 14 (modp2048), Group 19 (ECP-256), or Group 31 (Curve25519).",
        })

    # -------------------------------------------------------------
    # 5. Perfect Forward Secrecy (PFS)
    # Only penalize when there is positive wire evidence that PFS is OFF (a
    # captured CHILD_SA rekey with no fresh DH). If no rekey was captured, PFS
    # is Not Observed -- absence of evidence is not evidence of absence, so we
    # raise an informational note rather than a false vulnerability + penalty.
    # -------------------------------------------------------------
    if pfs_status == "Disabled":
        score -= 15
        deductions.append({"component": "Forward Secrecy", "points": 15, "reason": "Perfect Forward Secrecy (PFS) is disabled"})
        threats.append({
            "id": "THREAT-NO-PFS",
            "title": "Perfect Forward Secrecy (PFS) Not Enforced",
            "cve": "CWE-320",
            "severity": "MEDIUM",
            "cvss": 5.9,
            "likelihood": "Low",
            "impact": "Child SA keys are derived from the initial IKE SA key material without fresh DH exchange. If the long-term key is compromised, all past traffic can be retroactively decrypted.",
            "recommendation": "Enable PFS on Phase 2 / Child SA proposals (e.g., esp=aes256gcm16-modp2048!).",
        })
    elif pfs_status == "Not Observed":
        informational.append({
            "id": "INFO-PFS-NOT-OBSERVED",
            "title": "PFS Status Not Determinable from Capture",
            "detail": "No CHILD_SA rekey was captured, so PFS could not be confirmed either way. "
                      "It is negotiated in the encrypted phase-2 exchange and only revealed on rekey. "
                      "No score penalty is applied for an unobservable parameter.",
        })

    # -------------------------------------------------------------
    # 6. Replay Protection & Sequence Integrity
    # -------------------------------------------------------------
    if esp_analysis.get("duplicate_sequences", 0) > 0:
        score -= 20
        deductions.append({"component": "Replay Protection", "points": 20, "reason": "Duplicate ESP sequence numbers detected (potential replay attack)"})
        threats.append({
            "id": "THREAT-REPLAY-ANOMALY",
            "title": "Duplicate ESP Sequence Numbers Observed",
            "cve": "CWE-294",
            "severity": "HIGH",
            "cvss": 7.5,
            "likelihood": "Low",
            "impact": "Duplicate sequence numbers may indicate active replay attacks or malfunctioning anti-replay window state on the security gateway.",
            "recommendation": "Verify anti-replay window size is at least 64 or 128 packets and enable Extended Sequence Numbers (ESN).",
        })

    # Bound score in [0, 100]
    score = max(0, min(100, score))

    # Posture Classification
    if score >= 90:
        posture = "EXCELLENT / MILITARY-GRADE"
        posture_badge = "success"
        posture_color = "#10b981"  # Emerald
    elif score >= 75:
        posture = "SECURE / ENTERPRISE STANDARD"
        posture_badge = "primary"
        posture_color = "#06b6d4"  # Cyan
    elif score >= 50:
        posture = "MODERATE RISK / HARDENING REQUIRED"
        posture_badge = "warning"
        posture_color = "#f59e0b"  # Amber
    else:
        posture = "CRITICAL RISK / NON-COMPLIANT"
        posture_badge = "danger"
        posture_color = "#f43f5e"  # Rose

    # -------------------------------------------------------------
    # Compliance Matrix
    # -------------------------------------------------------------
    nist_compliant = (
        not is_ikev1
        and "3DES" not in cipher
        and "DES" not in cipher
        and "MD5" not in auth_algo
        and "SHA1" not in auth_algo
        and dh_id not in (1, 2, 5)
    )

    cnsa_compliant = (
        nist_compliant
        and ("AES-256" in cipher or "256" in cipher)
        and ("SHA2-384" in auth_algo or "SHA384" in auth_algo or "GCM" in cipher)
        and (dh_id in (14, 15, 16, 20, 21) or "2048" in dh_group or "384" in dh_group)
    )

    rfc8221_compliant = (
        "3DES" not in cipher
        and "DES" not in cipher
        and "MD5" not in auth_algo
    )

    compliance = {
        "nist_sp_800_77_r1": {
            "name": "NIST SP 800-77 Rev. 1 (Guide to IPsec VPNs)",
            "compliant": nist_compliant,
            "status": "PASS" if nist_compliant else "FAIL",
            "requirements": "IKEv2, AES-128/256, DH Group >= 14, SHA-256+, PFS Enabled",
        },
        "nsa_cnsa_suite": {
            "name": "NSA Commercial National Security Algorithm (CNSA)",
            "compliant": cnsa_compliant,
            "status": "PASS" if cnsa_compliant else "FAIL",
            "requirements": "AES-256-GCM, DH Group 14+ or Curve P-384, SHA-384",
        },
        "rfc_8221": {
            "name": "RFC 8221 (Cryptographic Algorithm Requirements for ESP/AH)",
            "compliant": rfc8221_compliant,
            "status": "PASS" if rfc8221_compliant else "FAIL",
            "requirements": "Prohibits DES, 3DES, and MD5; mandates AES-CBC and AES-GCM",
        },
    }

    # -------------------------------------------------------------
    # Remediation Code Snippets
    # -------------------------------------------------------------
    remediation_strongswan = """# /etc/ipsec.conf (Hardened strongSwan Deployment)
config setup
    charondebug="ike 1, knl 1, cfg 1"
    uniqueids=yes

conn secure-ipsec-vpn
    auto=start
    keyexchange=ikev2
    type=tunnel
    authby=secret
    left=192.168.50.10
    leftsubnet=10.0.1.0/24
    right=192.168.50.11
    rightsubnet=10.0.2.0/24
    # Hardened CNSA / NIST SP 800-77r1 Cipher Suites:
    ike=aes256gcm16-prfsha384-modp2048,aes256-sha256-modp2048!
    esp=aes256gcm16-modp2048,aes256-sha256-modp2048!
    dpdaction=restart
    dpddelay=30s
    ikelifetime=8h
    lifetime=1h
    rekeymargin=9m
"""

    remediation_cisco = """! Cisco IOS-XE / ASA Hardened IPsec Configuration
crypto ikev2 proposal HARDENED-IKEV2-PROP
 encryption aes-gcm-256
 prf sha384
 group 14 19

crypto ikev2 policy HARDENED-IKEV2-POLICY
 proposal HARDENED-IKEV2-PROP

crypto ipsec transform-set HARDENED-ESP-SET esp-gcm 256
 mode tunnel

crypto ipsec profile HARDENED-IPSEC-PROFILE
 set transform-set HARDENED-ESP-SET
 set pfs group14
 set security-association lifetime seconds 3600
"""

    # Fold any observability caveats recorded by the dissector (mode / ESP
    # cipher not determinable from a passive capture) into informational notes.
    for note in crypto_params.get("observability_notes", []):
        informational.append({
            "id": "INFO-OBSERVABILITY",
            "title": "Parameter Not Determinable from Passive Capture",
            "detail": note,
        })

    return {
        "security_score": score,
        "posture": posture,
        "posture_badge": posture_badge,
        "posture_color": posture_color,
        "deductions": deductions,
        "informational": informational,
        "threat_matrix": threats,
        "compliance": compliance,
        "remediations": {
            "strongswan": remediation_strongswan,
            "cisco": remediation_cisco,
        },
    }
