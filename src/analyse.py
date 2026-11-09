from __future__ import annotations
import json
import re
from pathlib import Path

def analyse(path: Path) -> dict:
    data = json.loads(path.read_text(encoding="utf-8"))
    txt = " | ".join(r.get("value", "") for r in data.get("records", []))
    findings = []
    score = 0
    if re.search(r"v=spf1", txt, re.I):
        score += 25
    else:
        findings.append({"issue": "missing_spf", "severity": "high"})
    if re.search(r"~all|\?all|\+all", txt):
        findings.append({"issue": "spf_not_hard_fail", "severity": "medium"})
    elif re.search(r"-all", txt):
        score += 15
    if re.search(r"v=DKIM1", txt, re.I):
        score += 25
    else:
        findings.append({"issue": "missing_dkim", "severity": "high"})
    m = re.search(r"v=DMARC1;([^|]+)", txt, re.I)
    if not m:
        findings.append({"issue": "missing_dmarc", "severity": "critical"})
    else:
        score += 20
        pol = m.group(1)
        if "p=reject" in pol:
            score += 20
        elif "p=quarantine" in pol:
            score += 10
        elif "p=none" in pol:
            findings.append({"issue": "dmarc_monitor_only", "severity": "medium"})
        if "rua=" not in pol:
            findings.append({"issue": "dmarc_missing_rua", "severity": "low"})
    band = "strong" if score >= 80 else "moderate" if score >= 50 else "weak"
    return {
        "domain": data.get("domain"),
        "score": score,
        "posture": band,
        "finding_count": len(findings),
        "findings": findings,
        "guidance": [
            "Move DMARC from p=none to quarantine then reject",
            "Use SPF -all once senders are inventoried",
            "Keep DKIM keys rotated and monitored",
        ],
    }
