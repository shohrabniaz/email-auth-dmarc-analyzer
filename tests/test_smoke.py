from pathlib import Path
import sys
ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from src.analyse import analyse

def test_detects_monitor_only():
    res = analyse(ROOT / "data" / "dns_txt_export.json")
    assert res["posture"] in {"moderate", "weak", "strong"}
    assert any(f["issue"] == "dmarc_monitor_only" for f in res["findings"])

if __name__ == "__main__":
    test_detects_monitor_only(); print("smoke_ok")
