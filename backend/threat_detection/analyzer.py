# threat_detection/analyzer.py

import os
import tempfile

from backend.threat_detection.hash_utils import compute_hashes
from backend.threat_detection.virustotal_api import scan_file_virustotal, get_report_virustotal
from backend.threat_detection.yara_scanner import scan_with_yara
from backend.threat_detection.clamav_scanner import scan_with_clamav
from backend.threat_detection.sandbox import submit_to_hybrid_analysis, get_hybrid_analysis_report
from backend.threat_detection.url_checker import extract_urls, check_url_reputation
from backend.threat_detection.report import generate_report

def analyze_email(file_path: str) -> dict:
    result = {
        "filename": os.path.basename(file_path)
    }

    # Step 1: Hashing (by file path)
    hashes = compute_hashes(file_path)
    result["hashes"] = hashes

    # Step 2: VirusTotal
    # Try to upload to VirusTotal (may be rate-limited) and fetch report
    try:
        vt_upload = scan_file_virustotal(file_path)
    except Exception:
        vt_upload = {"error": "vt upload failed"}
    result["virustotal_upload"] = vt_upload

    vt_report = get_report_virustotal(hashes.get("sha256")) if hashes.get("sha256") else {}
    result["virustotal"] = vt_report

    # ClamAV static scan (local)
    try:
        clam_res = scan_with_clamav(file_path)
    except Exception:
        clam_res = {"error": "clamav scan failed"}
    result["clamav"] = clam_res

    # Step 3: YARA
    yara_result = scan_with_yara(file_path)
    result["yara"] = yara_result

    # Step 4: Hybrid Analysis
    ha_submit = submit_to_hybrid_analysis(file_path)
    result["hybrid_analysis_submit"] = ha_submit

    if "sha256" in hashes:
        ha_report = get_hybrid_analysis_report(hashes["sha256"])
        result["hybrid_analysis_report"] = ha_report

    # Step 5: URL Extraction + Check
    try:
        with open(file_path, "rb") as f:
            content = f.read()
        text = content.decode("utf-8", errors="ignore")
        urls = extract_urls(text)
        url_checks = [check_url_reputation(url) for url in urls]
        result["urls"] = url_checks
    except Exception as e:
        result["urls"] = {"error": str(e)}

    return result


if __name__ == "__main__":
    # For testing
    import argparse

    parser = argparse.ArgumentParser()
    parser.add_argument("file", help="Path to .eml or attachment file")
    args = parser.parse_args()

    output = analyze_email(args.file)
    print(generate_report(output))
