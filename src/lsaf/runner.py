from datetime import datetime
from .probes import PROBES
def run_assessment(target: str):
    results = []
     
    for probe in PROBES:
        result = probe.execute(target)
        results.append(result)
    return {
    "target": target,
    "started_at": datetime.now().isoformat(),
    "status": "completed",
    "tests": results,
    "findings": [],
}