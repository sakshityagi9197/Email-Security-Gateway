import os
import tempfile
from typing import Any, Dict, List, Tuple, Optional

from backend.ingestion.ingestion import load_email
from backend.parser.parser import parse_eml, extract_attachments
from backend.schemas.class_schema import EmailMessage
from backend.validation_layer.dkim import verify_existing_dkim
from backend.validation_layer.spf import verify_spf
from backend.validation_layer.dmarc import validate_dmarc
from backend.threat_detection.analyzer import analyze_email
from backend.policy_attachment.Policy_Engine import evaluate_policy_for_eml
from backend.validation_layer.domain_checking import analyze_domain, extract_domain_from_address
from backend.routing.email_routing import route_email


def _analyze_attachments(eml_json: dict, verbose: bool = False) -> Tuple[List[Dict[str, Any]], bool]:
    results: List[Dict[str, Any]] = []
    any_malicious = False

    meta_attachments = (eml_json or {}).get("attachment") or []
    if not eml_json or not meta_attachments:
        return results, False

    with tempfile.TemporaryDirectory(prefix="email_attachments_") as tmpdir:
        saved = extract_attachments(eml_json, tmpdir)
        for filename, path in saved:
            analysis = analyze_email(path)
            analysis["filename"] = filename

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

    return results, any_malicious


def _derive_threat_score(attachment_results: List[Dict[str, Any]], dmarc_ok: bool, dkim_ok: bool, email_scan: Optional[Dict[str, Any]] = None) -> int:
    score = 0

    def _infer_vt_mal(vt_obj: Optional[Dict[str, Any]]) -> int:
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

    def _has_yara_matches(yara_obj: Optional[Dict[str, Any]]) -> bool:
        yr = yara_obj or {}
        matches = []
        if isinstance(yr, dict):
            matches = yr.get("matches") or []
        return isinstance(matches, list) and len(matches) > 0

    # Attachment-level
    for att in attachment_results:
        if _infer_vt_mal(att.get("virustotal") or {}) > 0:
            score = max(score, 90)
        if _has_yara_matches(att.get("yara") or {}):
            score = max(score, 70)

    # Email-level
    if isinstance(email_scan, dict):
        if _infer_vt_mal(email_scan.get("virustotal") or {}) > 0:
            score = max(score, 80)
        if _has_yara_matches(email_scan.get("yara") or {}):
            score = max(score, 65)

    if not dmarc_ok:
        score = min(100, max(score, score + 20))

    return int(score)


def analyze_eml(eml_path: str, policy_yaml_path: Optional[str] = None, verbose: bool = False) -> Dict[str, Any]:
    # Load and parse
    raw_eml = load_email(eml_path)
    eml_json = parse_eml(raw_eml)

    # Build object
    email_obj = EmailMessage()
    email_obj.load_eml_data(eml_json, eml_path)
    email_obj.raw_eml_file = raw_eml

    # DKIM
    dkim_ok, dkim_msg = verify_existing_dkim(raw_eml)

    # SPF per received IP
    spf_checks: List[Tuple[str, bool, str, str]] = []
    ips = email_obj.received_ips or []
    for ip in ips:
        try:
            is_valid, result_code, message = verify_spf(raw_eml, ip)
        except Exception as e:
            is_valid, result_code, message = False, "error", f"SPF check error: {e}"
        spf_checks.append((ip, is_valid, result_code, message))
    if not spf_checks:
        try:
            is_valid, result_code, message = verify_spf(raw_eml, "127.0.0.1")
            spf_checks.append(("127.0.0.1", is_valid, result_code, message))
        except Exception as e:
            spf_checks.append(("127.0.0.1", False, "error", f"SPF fallback error: {e}"))

    # DMARC
    dmarc_ok, dmarc_result, dmarc_policy, dmarc_message = validate_dmarc(raw_eml, dkim_ok, spf_checks)

    # Threat detection: email-level scan + attachments
    email_scan = analyze_email(eml_path)
    attachment_results, attachments_malicious = _analyze_attachments(eml_json, verbose=verbose)

    # Policy and threat score
    if policy_yaml_path is None:
        default_path = os.path.normpath(
            os.path.join(os.path.dirname(__file__), "..", "policy_attachment", "yaml_file.yaml")
        )
        policy_yaml_path = default_path

    computed_threat = _derive_threat_score(attachment_results, dmarc_ok, dkim_ok, email_scan=email_scan)
    if os.path.exists(policy_yaml_path):
        policy_eval = evaluate_policy_for_eml(eml_path, policy_yaml_path, quiet=not verbose, threat_score=computed_threat)
        policy = {
            "yaml": policy_yaml_path,
            "matches": policy_eval.get("matches", []),
            "final_action": policy_eval.get("final_action", "none"),
            "final_rule": policy_eval.get("final_rule"),
            "final_reason": policy_eval.get("final_reason"),
            "threat_score": computed_threat,
        }
    else:
        policy = {"status": "skipped", "reason": f"no policy file: {policy_yaml_path}", "threat_score": computed_threat}

    # Domain spoofing analysis
    from_domain = extract_domain_from_address(email_obj.email_from or "")
    domain_risk = analyze_domain(from_domain) if from_domain else None

    # Final decision with priority: Policy > Threat detection > Domain spoofing
    threat_score = int(policy.get("threat_score") or 0)
    reasons: List[str] = []

    policy_action = (policy.get("final_action") if isinstance(policy, dict) else None) or "none"
    if policy_action in {"block", "reject"}:
        final_decision = "BLOCK"
        reasons.append(f"Policy action: {policy_action}")
    elif policy_action == "quarantine":
        final_decision = "QUARANTINE"
        reasons.append("Policy action: quarantine")
    else:
        # Threat detection failures -> quarantine (not block)
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
            # Domain spoofing
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

    result: Dict[str, Any] = {
        "email": {
            "subject": email_obj.subject,
            "from": email_obj.email_from,
            "to": email_obj.email_to,
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
        "email_scan": email_scan,
        "policy": policy,
        "domain_risk": domain_risk,
        "final_decision": final_decision,
        "reasons": reasons,
    }

    # Routing
    routed_path = route_email(eml_path, result)
    if routed_path:
        result["routed_path"] = routed_path

    return result
