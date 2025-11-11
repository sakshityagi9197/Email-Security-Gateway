import argparse
import os
import tempfile
from typing import Any, Dict, List, Tuple

from backend.ingestion.ingestion import load_email
from backend.parser.parser import parse_eml, extract_attachments
from backend.schemas.class_schema import EmailMessage
from backend.validation_layer.dkim import verify_existing_dkim
from backend.validation_layer.spf import verify_spf
from backend.validation_layer.dmarc import validate_dmarc
from backend.threat_detection.analyzer import analyze_email
from backend.validation_layer.domain_checking import analyze_domain, extract_domain_from_address
from backend.policy_attachment.Policy_Engine import evaluate_policy_for_eml
from backend.routing.email_routing import route_email


def analyze_attachments_inline(eml_json: dict, verbose: bool = False) -> Tuple[List[Dict[str, Any]], bool]:
    results: List[Dict[str, Any]] = []
    any_malicious = False

    # Count metadata attachments regardless of raw content presence
    meta_attachments = (eml_json or {}).get("attachment") or []
    if not eml_json or not meta_attachments:
        if verbose:
            print("Attachments: none found")
        return results, False

    with tempfile.TemporaryDirectory(prefix="email_attachments_") as tmpdir:
        saved = extract_attachments(eml_json, tmpdir)
        if verbose:
            print(f"Attachments found: {len(meta_attachments)}")
            print(f"Analyzing attachments (content available): {len(saved)} file(s)")
            if len(saved) == 0 and len(meta_attachments) > 0:
                print("Note: Attachment content not present in parsed JSON. Enable include_attachment_data in parser.")
        for filename, path in saved:
            if verbose:
                print(f" - Scanning attachment: {filename}")
            analysis = analyze_email(path)
            analysis["filename"] = filename

            # Infer maliciousness
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


def derive_threat_score(attachment_results: List[Dict[str, Any]], dmarc_ok: bool, dkim_ok: bool, email_scan: Dict[str, Any] | None = None) -> int:
    """Best-effort threat score 0-100 from analysis results.

    Heuristic:
    - Any VT malicious detections -> at least 90
    - Any YARA matches -> at least 70
    - DMARC failure adds up to 20 (cap 100)
    - Otherwise 0
    """
    score = 0

    def _infer_vt_mal(vt_obj: Dict[str, Any] | None) -> int:
        vt = vt_obj or {}
        vt_stats = (
            ((vt.get("data") or {}).get("attributes") or {}).get("last_analysis_stats")
            if isinstance(vt, dict)
            else {}
        )
        if isinstance(vt_stats, dict):
            try:
                return int(vt_stats.get("malicious", 0) or 0)
            except Exception:
                return 0
        return 0

    def _has_yara_matches(yara_obj: Dict[str, Any] | None) -> bool:
        yr = yara_obj or {}
        matches = []
        if isinstance(yr, dict):
            matches = yr.get("matches") or []
        return isinstance(matches, list) and len(matches) > 0

    # Attachment-level signals
    for att in attachment_results:
        vt = att.get("virustotal") or {}
        vt_mal = _infer_vt_mal(vt)
        if vt_mal > 0:
            score = max(score, 90)

        if _has_yara_matches(att.get("yara") or {}):
            score = max(score, 70)

    # Email-level signals (scan the .eml itself)
    if isinstance(email_scan, dict):
        if _infer_vt_mal(email_scan.get("virustotal") or {}) > 0:
            score = max(score, 80)
        if _has_yara_matches(email_scan.get("yara") or {}):
            score = max(score, 65)

    if not dmarc_ok:
        score = min(100, max(score, score + 20))

    return int(score)


def main():
    parser = argparse.ArgumentParser(description="EmailSecurity - Validate a single .eml file")
    parser.add_argument(
        "eml",
        nargs="?",
        default=r"backend/samples/Job Notification sample.eml",
        help="Path to .eml file",
    )
    parser.add_argument(
        "-v",
        "--verbose",
        action="store_true",
        help="Print step-by-step progress",
    )
    parser.add_argument(
        "-p",
        "--policy",
        default=None,
        help="Path to policy YAML (defaults to backend/policy_attachment/yaml_file.yaml)",
    )
    args = parser.parse_args()

    # 1) Load and parse
    if args.verbose:
        print(f"Loading EML: {args.eml}")
    raw_eml = load_email(args.eml)

    if args.verbose:
        print("Parsing EML...")
    eml_json = parse_eml(raw_eml)

    # 2) Email object
    if args.verbose:
        print("Updating email object from parsed data...")
    email_obj = EmailMessage()
    email_obj.load_eml_data(eml_json, args.eml)
    email_obj.raw_eml_file = raw_eml

    # 3) DKIM
    if args.verbose:
        print("Checking DKIM...")
    dkim_ok, dkim_msg = verify_existing_dkim(raw_eml)

    # 4) SPF across received IPs
    spf_checks: List[Tuple[str, bool, str, str]] = []
    ips = email_obj.received_ips or []
    if args.verbose:
        print(f"Checking SPF on {len(ips) if ips else 0} received IP(s)...")
    for ip in ips:
        try:
            if args.verbose:
                print(f" - SPF for IP {ip}...")
            is_valid, result_code, message = verify_spf(raw_eml, ip)
        except Exception as e:
            is_valid, result_code, message = False, "error", f"SPF check error: {e}"
        spf_checks.append((ip, is_valid, result_code, message))

    if not spf_checks:
        try:
            if args.verbose:
                print(" - No received IPs. Doing fallback SPF check (127.0.0.1)...")
            is_valid, result_code, message = verify_spf(raw_eml, "127.0.0.1")
            spf_checks.append(("127.0.0.1", is_valid, result_code, message))
        except Exception as e:
            spf_checks.append(("127.0.0.1", False, "error", f"SPF fallback error: {e}"))

    # 5) DMARC
    if args.verbose:
        print("Validating DMARC...")
    dmarc_ok, dmarc_result, dmarc_policy, dmarc_message = validate_dmarc(
        raw_eml, dkim_ok, spf_checks
    )

    # 6) Threat detection
    # 6.1) Email-level scan (YARA/VT/URLs)
    email_scan = analyze_email(args.eml)
    # 6.2) Attachments
    attachment_results, attachments_malicious = analyze_attachments_inline(eml_json, verbose=args.verbose)

    # 7) Policy matching (and compute threat score for policy)
    policy_yaml = args.policy
    if policy_yaml is None:
        policy_yaml = os.path.normpath(
            os.path.join(os.path.dirname(__file__), "backend", "policy_attachment", "yaml_file.yaml")
        )

    if os.path.exists(policy_yaml):
        if args.verbose:
            print("Matching policy...")
        # Compute a threat score to feed policy engine (includes email-level scan)
        computed_threat = derive_threat_score(attachment_results, dmarc_ok, dkim_ok, email_scan=email_scan)
        if args.verbose:
            print(f"Policy threat_score: {computed_threat}")
        policy_eval = evaluate_policy_for_eml(
            args.eml, policy_yaml, quiet=not args.verbose, threat_score=computed_threat
        )
        policy = {
            "yaml": policy_yaml,
            "matches": policy_eval.get("matches", []),
            "final_action": policy_eval.get("final_action", "none"),
            "final_rule": policy_eval.get("final_rule"),
            "final_reason": policy_eval.get("final_reason"),
            "threat_score": computed_threat,
        }
    else:
        if args.verbose:
            print(f"Matching policy... (skipped: no yaml at {policy_yaml})")
        policy = {"status": "skipped", "reason": f"no policy file: {policy_yaml}"}

    # 8) Domain spoofing risk (From domain)
    from_domain = extract_domain_from_address(email_obj.email_from or "")
    domain_risk = analyze_domain(from_domain) if from_domain else None

    # 9) Final decision with priority: Policy > Threat detection > Domain spoofing
    reasons: List[str] = []
    threat_score = policy.get("threat_score") if isinstance(policy, dict) else None
    threat_score = int(threat_score) if threat_score is not None else 0

    # Policy first
    policy_action = (policy.get("final_action") if isinstance(policy, dict) else None) or "none"
    if policy_action in {"block", "reject"}:
        final_decision = "BLOCK"
        reasons.append(f"Policy action: {policy_action}")
    elif policy_action == "quarantine":
        final_decision = "QUARANTINE"
        reasons.append("Policy action: quarantine")
    else:
        # Threat detection next (treat failures as quarantine)
        threat_fail = bool(attachments_malicious or threat_score >= 60 or (not dmarc_ok))
        if threat_fail:
            final_decision = "QUARANTINE"
            if attachments_malicious:
                reasons.append("Threat detection: malicious attachment(s)")
            elif threat_score >= 60:
                reasons.append(f"Threat detection: elevated score {threat_score}")
            else:
                reasons.append(f"DMARC non-compliant: {dmarc_result} - {dmarc_message}")
        else:
            # Domain spoofing last
            dr = domain_risk or {}
            flags = dr.get("flags", {}) if isinstance(dr, dict) else {}
            list_info = dr.get("list", {}) if isinstance(dr, dict) else {}
            domain_fail = False
            try:
                domain_fail = bool(
                    list_info.get("status") == "block"
                    or (int(dr.get("risk_score", 0)) >= 60)
                    or flags.get("homoglyph_or_typosquat")
                    or flags.get("idn_homograph")
                    or flags.get("has_bidi_controls")
                    or flags.get("has_zero_width")
                    or flags.get("suspicious_tld")
                )
            except Exception:
                domain_fail = False

            if domain_fail:
                final_decision = "QUARANTINE"
                reasons.append("Domain spoofing risk detected")
            else:
                final_decision = "FORWARD"
                reasons.append("All checks passed")

    # 10) Routing (save malicious/quarantined emails)
    routed_path = route_email(args.eml, {
        "email": {
            "subject": email_obj.subject,
            "from": email_obj.email_from,
            "date": email_obj.date,
            "path": args.eml,
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
        "email_scan": email_scan,
        "domain_risk": domain_risk,
        "policy": policy,
        "final_decision": final_decision,
        "reasons": reasons,
    })

    if args.verbose:
        print(f"Final decision: {final_decision}")
        if reasons:
            for r in reasons:
                print(f" - {r}")
        if routed_path:
            print(f"Routed to: {routed_path}")
    else:
        print(f"Final Decision: {final_decision}")
        if reasons:
            print("Reasons:")
            for r in reasons:
                print(f" - {r}")
        if routed_path:
            print(f"Routed to: {routed_path}")


if __name__ == "__main__":
    main()
