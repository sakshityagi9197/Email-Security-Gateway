from .sandbox import submit_to_hybrid_analysis, get_hybrid_analysis_report
from .clamav_scanner import scan_with_clamav

def run_sandbox_checks(file_path: str, sha256_hash: str) -> dict:
    results = {}

    # Local ClamAV scan
    results["clamav"] = scan_with_clamav(file_path)

    # Hybrid Analysis submission + report
    ha_submission = submit_to_hybrid_analysis(file_path)
    results["hybrid_analysis_submission"] = ha_submission

    if "error" not in ha_submission:
        results["hybrid_analysis_report"] = get_hybrid_analysis_report(sha256_hash)

    return results
