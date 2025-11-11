from __future__ import annotations

import os
import tempfile
from typing import Any, Dict, List, Tuple

from backend.ingestion.ingestion import load_email
from backend.parser.parser import parse_eml, extract_attachments
from backend.schemas.class_schema import EmailMessage
from backend.validation_layer.dkim import verify_existing_dkim
from backend.validation_layer.spf import verify_spf
from backend.validation_layer.dmarc import validate_dmarc
from backend.validation_layer.domain_checking import (
    analyze_domain,
    extract_domain_from_address,
)
from backend.threat_detection.analyzer import analyze_email
from backend.policy_attachment.Policy_Engine import evaluate_policy_for_eml


def _analyze_attachments(eml_json: dict, verbose: bool = False) -> Tuple[List[Dict[str, Any]], bool]:
    """Save and analyze attachments. Returns list of results and malicious flag.

    Heuristic for malicious:
    - VirusTotal: last_analysis_stats.malicious > 0
    - YARA: any matches
    - Hybrid Analysis: presence of error doesn't mark malicious; any explicit verdicts can be interpreted upstream
    - URL checks: status >= 400 doesn't mark malicious; this is informational only
    """
    results: List[Dict[str, Any]] = []
    any_malicious = False

    # Quick exit if no attachments in eml_json
    if not eml_json or not eml_json.get("attachment"):
        if verbose:
            print("Attachments: none found")
        return results, False

    with tempfile.TemporaryDirectory(prefix="email_attachments_") as tmpdir:
        saved = extract_attachments(eml_json, tmpdir)
        if verbose:
            print(f"Analyzing attachments: {len(saved)} file(s)")
        for filename, path in saved:
            if verbose:
                print(f" - Scanning attachment: {filename}")
            analysis = analyze_email(path)
            analysis["filename"] = filename

            # Try to infer maliciousness
            vt = analysis.get("virustotal") or {}
            vt_stats = (
                ((vt.get("data") or {}).get("attributes") or {}).get("last_analysis_stats")
                if isinstance(vt, dict)
                else {}
            )
            vt_mal = 0
            if isinstance(vt_stats, dict):
                vt_mal = int(vt_stats.get("malicious", 0) or 0)

            yara_res = analysis.get("yara") or {}
            yara_matches = []
            if isinstance(yara_res, dict):
                yara_matches = yara_res.get("matches") or []

            is_malicious = vt_mal > 0 or (isinstance(yara_matches, list) and len(yara_matches) > 0)
            analysis["is_malicious"] = is_malicious
            results.append(analysis)

            if is_malicious:
                any_malicious = True
                if verbose:
                    print(f"   -> Result: MALICIOUS (VT malicious={vt_mal}, YARA matches={len(yara_matches)})")
            elif verbose:
                print("   -> Result: clean")

    return results, any_malicious


def validate_email(eml_path: str, verbose: bool = False, policy_yaml_path: str | None = None) -> Dict[str, Any]:
    """Run full validation pipeline for a single .eml file.

    Steps:
    - Ingest + parse
    - Build EmailMessage object
    - DKIM, SPF, DMARC checks
    - Attachment threat analysis
    - Final pass/fail decision

    Returns a structured dict with details and `final_decision` in {"PASS","FAIL"}.
    """
    # 1) Load raw and parse
    if verbose:
        print(f"Loading EML: {eml_path}")
    raw_eml = load_email(eml_path)
    if verbose:
        print("Parsing EML...")
    eml_json = parse_eml(raw_eml)

    # 2) Object model
    if verbose:
        print("Updating email object from parsed data...")
    email_obj = EmailMessage()
    email_obj.load_eml_data(eml_json, eml_path)
    email_obj.raw_eml_file = raw_eml

    # 3) DKIM
    if verbose:
        print("Checking DKIM...")
    dkim_ok, dkim_msg = verify_existing_dkim(raw_eml)

    # 4) SPF (evaluate against each received IP; consider pass if any pass)
    spf_checks: List[Tuple[str, bool, str, str]] = []  # (ip, is_valid, result_code, message)
    ips = email_obj.received_ips or []
    if verbose:
        print(f"Checking SPF on {len(ips) if ips else 0} received IP(s)...")
    for ip in ips:
        try:
            if verbose:
                print(f" - SPF for IP {ip}...")
            is_valid, result_code, message = verify_spf(raw_eml, ip)
        except Exception as e:  # defensive
            is_valid, result_code, message = False, "error", f"SPF check error: {e}"
        spf_checks.append((ip, is_valid, result_code, message))

    # If no received IPs, try a single SPF using from address and loopback IP (informational)
    if not spf_checks:
        try:
            # Fallback best-effort: from-address domain + 127.0.0.1 (won't PASS, but records may be looked up)
            if verbose:
                print(" - No received IPs. Doing fallback SPF check (127.0.0.1)...")
            is_valid, result_code, message = verify_spf(raw_eml, "127.0.0.1")
            spf_checks.append(("127.0.0.1", is_valid, result_code, message))
        except Exception as e:
            spf_checks.append(("127.0.0.1", False, "error", f"SPF fallback error: {e}"))

    # 5) DMARC
    if verbose:
        print("Validating DMARC...")
    dmarc_ok, dmarc_result, dmarc_policy, dmarc_message = validate_dmarc(
        raw_eml, dkim_ok, spf_checks
    )

    # 6) Attachments threat detection
    attachment_results, attachments_malicious = _analyze_attachments(eml_json, verbose=verbose)

    # 6.2) Domain risk (From domain)
    from_domain = extract_domain_from_address(email_obj.email_from or "")
    domain_risk = analyze_domain(from_domain) if from_domain else None

    # 6.5) Policy matching (YAML engine)
    if policy_yaml_path is None:
        # default bundled sample policy file if available
        default_path = os.path.join(
            os.path.dirname(__file__), "..", "policy_attachment", "yaml_file.yaml"
        )
        policy_yaml_path = os.path.normpath(default_path)

    policy: Dict[str, Any]
    if os.path.exists(policy_yaml_path):
        if verbose:
            print("Matching policy...")
        policy_eval = evaluate_policy_for_eml(eml_path, policy_yaml_path, quiet=not verbose)
        policy = {
            "yaml": policy_yaml_path,
            "matches": policy_eval.get("matches", []),
            "final_action": policy_eval.get("final_action", "none"),
            "final_rule": policy_eval.get("final_rule"),
            "final_reason": policy_eval.get("final_reason"),
        }
    else:
        if verbose:
            print(f"Matching policy... (skipped: no yaml at {policy_yaml_path})")
        policy = {"status": "skipped", "reason": f"no policy file: {policy_yaml_path}"}

    # 7) Final decision policy
    reasons: List[str] = []
    if not dmarc_ok:
        reasons.append(f"DMARC {dmarc_result}: {dmarc_message}")
    if attachments_malicious:
        reasons.append("Malicious attachment(s) detected")

    # Incorporate policy engine action into decision
    policy_action = policy.get("final_action") if isinstance(policy, dict) else None
    if policy_action in {"block", "quarantine"}:
        reasons.append(f"Policy action: {policy_action} (rule={policy.get('final_rule')})")

    final_decision = "PASS" if not reasons else "FAIL"

    result = {
        "email": {
            "subject": email_obj.subject,
            "from": email_obj.email_from,
            "date": email_obj.date,
            "path": eml_path,
        },
        "auth": {
            "dkim": {"passed": bool(dkim_ok), "message": dkim_msg},
            "spf": [
                {"ip": ip, "passed": bool(valid and code == "pass"), "code": code, "message": msg}
                for (ip, valid, code, msg) in spf_checks
            ],
            "dmarc": {
                "compliant": bool(dmarc_ok),
                "result": dmarc_result,
                "policy": dmarc_policy,
                "message": dmarc_message,
            },
        },
        "attachments": attachment_results,
        "domain_risk": domain_risk,
        "policy": policy,
        "final_decision": final_decision,
        "reasons": reasons,
    }

    if verbose:
        print(f"Final decision: {final_decision}")
        if reasons:
            for r in reasons:
                print(f" - {r}")

    return result


def main_cli(eml_path: str, verbose: bool = True) -> None:
    """Convenience CLI printer for debugging/manual runs."""
    result = validate_email(eml_path, verbose=verbose)

    print("Email:")
    print(f"  From   : {result['email']['from']}")
    print(f"  Subject: {result['email']['subject']}")
    print(f"  Date   : {result['email']['date']}")
    print()

    print("Auth:")
    print(f"  DKIM   : {'PASS' if result['auth']['dkim']['passed'] else 'FAIL'} - {result['auth']['dkim']['message']}")
    for spf in result["auth"]["spf"]:
        print(
            f"  SPF[{spf['ip']}] : {'PASS' if spf['passed'] else 'FAIL'} ({spf['code']}) - {spf['message']}"
        )
    d = result["auth"]["dmarc"]
    print(f"  DMARC  : {'PASS' if d['compliant'] else 'FAIL'} ({d['result']}) - {d['message']}")
    print()

    if result["attachments"]:
        print("Attachments:")
        for att in result["attachments"]:
            print(
                f"  {att.get('filename','?')} - {'MALICIOUS' if att.get('is_malicious') else 'clean'}"
            )
        print()

    if result.get("domain_risk"):
        dr = result["domain_risk"]
        print("Domain Risk:")
        print(f"  From domain : {dr['domain']} -> {dr['ascii_domain']}")
        print(f"  Risk score  : {dr['risk_score']}")
        ls = dr.get('list') or {}
        passes = bool(ls.get('passes', True))
        print(f"  List status : {ls.get('status','none')} (allow={ls.get('allow_match')}, block={ls.get('block_match')})")
        print(f"  Checks      : {'PASS' if passes else 'FAIL'}")
        if dr.get("reasons"):
            print("  Reasons:")
            for r in dr["reasons"]:
                print(f"    - {r}")
        print()

    print(f"Final Decision: {result['final_decision']}")
    if result["reasons"]:
        print("Reasons:")
        for r in result["reasons"]:
            print(f"  - {r}")
