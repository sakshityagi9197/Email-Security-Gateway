import os
import shutil
import yaml
import csv
import re
from email import policy
from email.parser import BytesParser
from datetime import datetime

# ========== CONFIGURATION ==========
import json
from typing import Optional

POLICY_DIR = os.path.dirname(os.path.abspath(__file__))
ACTIVE_META = os.path.join(POLICY_DIR, ".active_policy.json")
QUARANTINE_DIR = os.path.join(POLICY_DIR, "..", "routing", "quarantine")
QUARANTINE_REPORT = os.path.join(QUARANTINE_DIR, "quarantine_report.csv")

def get_active_policy_path() -> Optional[str]:
    """Get the path of the currently active policy"""
    try:
        if os.path.exists(ACTIVE_META):
            with open(ACTIVE_META, "r", encoding="utf-8") as f:
                data = json.load(f)
            if isinstance(data, dict) and "path" in data:
                policy_path = data["path"]
                if os.path.exists(policy_path):
                    return policy_path
    except Exception:
        pass
    
    # Fallback to default policy if exists
    default_path = os.path.join(POLICY_DIR, "default.yaml")
    if os.path.exists(default_path):
        return default_path
    return None

# ========== QUARANTINE REPORT ==========
def update_quarantine_report(file_path, rule_id, reason, *, quiet: bool = False):
    """Add entry to quarantine report CSV file"""
    try:
        os.makedirs(QUARANTINE_DIR, exist_ok=True)
        filename = os.path.basename(file_path)
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        
        # Check if file exists to write header
        file_exists = os.path.exists(QUARANTINE_REPORT)
        
        with open(QUARANTINE_REPORT, mode='a', newline='', encoding='utf-8') as file:
            writer = csv.writer(file)
            if not file_exists:
                writer.writerow(['Filename', 'Rule ID', 'Reason', 'Timestamp'])
            writer.writerow([filename, rule_id, reason, timestamp])
        
        if not quiet:
            print(f"✅ Added to quarantine report: {filename}")
        
    except Exception as e:
        print(f"❌ Error updating report: {e}")

# ========== QUARANTINE FILE ==========
def store_quarantined_file(file_path, filename, *, quiet: bool = False):
    """Copy file to quarantine directory"""
    try:
        os.makedirs(QUARANTINE_DIR, exist_ok=True)
        destination_path = os.path.join(QUARANTINE_DIR, filename)
        shutil.copy(file_path, destination_path)
        if not quiet:
            print(f"📦 Quarantined: {filename}")
        return destination_path
    except Exception as e:
        print(f"❌ Error quarantining file: {e}")
        return None

# ========== LOAD POLICY RULES (WITH CACHING) ==========
# MEDIUM-04 fix: Cache policy files to avoid reloading on every request
_policy_cache = {}
_policy_mtimes = {}


def load_policy_rules(yaml_path, *, quiet: bool = False):
    """
    Load security policy rules from YAML file with caching (MEDIUM-04 fix)

    Caching strategy:
    - Checks file modification time before reloading
    - Returns cached rules if file hasn't changed
    - Reduces disk I/O on repeated requests
    - Automatically updates when policy file is modified
    """
    try:
        # Get current modification time
        current_mtime = os.path.getmtime(yaml_path)

        # Check cache
        if yaml_path in _policy_cache:
            cached_mtime = _policy_mtimes.get(yaml_path, 0)
            if cached_mtime == current_mtime:
                # Cache hit - return cached rules
                return _policy_cache[yaml_path]

        # Cache miss or file changed - load from disk
        with open(yaml_path, 'r', encoding='utf-8') as file:
            policy_data = yaml.safe_load(file)
            rules = policy_data.get("rules", [])

        # Update cache
        _policy_cache[yaml_path] = rules
        _policy_mtimes[yaml_path] = current_mtime

        if not quiet:
            print(f"📋 Loaded {len(rules)} security rules (cached)")

        return rules

    except Exception as e:
        print(f"❌ Error loading policy: {e}")
        return []


def clear_policy_cache():
    """Clear policy cache (useful after policy updates)"""
    _policy_cache.clear()
    _policy_mtimes.clear()

# ========== LOAD EMAIL ==========
def load_email(eml_path, *, quiet: bool = False):
    """Load and parse email file"""
    try:
        with open(eml_path, 'rb') as f:
            email_obj = BytesParser(policy=policy.default).parse(f)
            if not quiet:
                print(f"📧 Loaded email: {os.path.basename(eml_path)}")
            return email_obj
    except Exception as e:
        print(f"❌ Error loading email: {e}")
        return None

# ========== MATCH POLICY ==========
def match_policy(email_obj, rules, *, quiet: bool = False, threat_score: int | None = None):
    """Check email against security rules"""
    matches = []
    
    for rule in rules:
        rule_id = rule.get('id', 'unknown')
        conditions = rule.get('conditions', {})
        action = rule.get('action', 'unknown')
        reason = rule.get('reasoning', 'No reason given')
        
        # Check for dangerous file attachments
        if 'attachment_extension' in conditions:
            dangerous_extensions = conditions['attachment_extension']
            for part in email_obj.walk():
                filename = part.get_filename()
                if filename:
                    file_extension = filename.split('.')[-1].lower()
                    if file_extension in dangerous_extensions:
                        matches.append((rule_id, action, reason))
                        if not quiet:
                            print(f"🚨 Found dangerous file: {filename}")
        
        # Check for suspicious words in subject
        if 'subject_contains' in conditions:
            subject = email_obj.get('subject', '')
            suspicious_words = conditions['subject_contains']
            for word in suspicious_words:
                if word.lower() in subject.lower():
                    matches.append((rule_id, action, reason))
                    if not quiet:
                        print(f"🚨 Found suspicious word in subject: {word}")
        
        # Check for suspicious words in body
        if 'body_contains' in conditions:
            suspicious_words = conditions['body_contains']
            for part in email_obj.walk():
                if part.get_content_type() == 'text/plain':
                    try:
                        body = part.get_payload(decode=True).decode('utf-8', errors='ignore')
                        for word in suspicious_words:
                            if word.lower() in body.lower():
                                matches.append((rule_id, action, reason))
                                if not quiet:
                                    print(f"🚨 Found suspicious word in body: {word}")
                    except:
                        continue
        
        # Check for personal information patterns
        if 'contains_patterns' in conditions:
            patterns = conditions['contains_patterns']
            for part in email_obj.walk():
                if part.get_content_type() == 'text/plain':
                    try:
                        body = part.get_payload(decode=True).decode('utf-8', errors='ignore')
                        for pattern in patterns:
                            if re.search(pattern, body):
                                matches.append((rule_id, action, reason))
                                if not quiet:
                                    print(f"🚨 Found personal information pattern")
                    except:
                        continue
        
        # Check attachment count and size
        if 'attachment_count_greater_than' in conditions:
            attachment_count = 0
            for part in email_obj.walk():
                if part.get_filename():
                    attachment_count += 1
            if attachment_count > conditions['attachment_count_greater_than']:
                matches.append((rule_id, action, reason))
                if not quiet:
                    print(f"🚨 Too many attachments: {attachment_count}")
        
        # Threat score check (provided by caller; defaults to 0)
        if 'threat_score_greater_than' in conditions:
            effective_score = int(threat_score) if threat_score is not None else 0
            try:
                threshold = int(conditions['threat_score_greater_than'])
            except Exception:
                threshold = 0
            if effective_score > threshold:
                matches.append((rule_id, action, reason))
                if not quiet:
                    print(f"🚨 High threat score: {effective_score}")

        if 'threat_score_less_than' in conditions:
            effective_score = int(threat_score) if threat_score is not None else 0
            try:
                threshold_lt = int(conditions['threat_score_less_than'])
            except Exception:
                threshold_lt = 0
            if effective_score < threshold_lt:
                matches.append((rule_id, action, reason))
                if not quiet:
                    print(f"✅ Low threat score: {effective_score}")
    
    return matches

# ========== RESOLVE CONFLICTING ACTIONS ==========
def resolve_final_action(matches):
    """Determine the most severe action from all matches."""
    priority = {'block': 3, 'quarantine': 2, 'allow': 1, 'none': 0}
    final_action = 'none'
    final_rule = None
    final_reason = None
    for rule_id, action, reason in matches:
        if priority.get(action, 0) > priority.get(final_action, 0):
            final_action = action
            final_rule = rule_id
            final_reason = reason
    return final_action, final_rule, final_reason


# ========== PUBLIC API (reusable) ==========
def evaluate_policy_for_eml(eml_path: str, yaml_path: str | None = None, *, quiet: bool = True, threat_score: int | None = None):
    """Evaluate policy rules for a given EML without side effects.

    Args:
        eml_path: Path to the email file to evaluate
        yaml_path: Optional path to policy file. If None, uses active policy
        quiet: Whether to suppress output messages
        threat_score: Optional threat score to use in evaluation

    Returns:
        dict with structure:
        {
            'matches': [(rule_id, action, reason), ...],
            'final_action': 'allow|quarantine|block|none',
            'final_rule': str|None,
            'final_reason': str|None
        }
    """
    # Get active policy path if none provided
    if yaml_path is None:
        yaml_path = get_active_policy_path()
        if yaml_path is None:
            return {
                "matches": [],
                "final_action": "none",
                "final_rule": None,
                "final_reason": "no active policy found",
            }
    
    # Load and validate policy rules
    rules = load_policy_rules(yaml_path, quiet=quiet)
    if not rules:
        return {
            "matches": [],
            "final_action": "none",
            "final_rule": None,
            "final_reason": "no rules loaded",
        }

    email_obj = load_email(eml_path, quiet=quiet)
    if not email_obj:
        return {
            "matches": [],
            "final_action": "none",
            "final_rule": None,
            "final_reason": "failed to load email",
        }

    matches = match_policy(email_obj, rules, quiet=quiet, threat_score=threat_score)
    final_action, final_rule, final_reason = resolve_final_action(matches)

    return {
        "matches": matches,
        "final_action": final_action,
        "final_rule": final_rule,
        "final_reason": final_reason,
    }

# ========== MAIN FUNCTION ==========
def main():
    """CLI utility to test policy evaluation"""
    import argparse
    
    parser = argparse.ArgumentParser(description="Email Security Policy Evaluator")
    parser.add_argument("--email", "-e", help="Path to email file to evaluate")
    parser.add_argument("--policy", "-p", help="Path to policy file (optional, uses active policy if not specified)")
    parser.add_argument("--quiet", "-q", action="store_true", help="Suppress detailed output")
    args = parser.parse_args()
    
    if not args.email:
        print("❌ No email file specified")
        parser.print_help()
        return

    if not os.path.exists(args.email):
        print(f"❌ Email file not found: {args.email}")
        return
        
    # Use specified policy or find active one
    policy_path = args.policy
    if not policy_path:
        policy_path = get_active_policy_path()
        if not policy_path:
            print("❌ No active policy found")
            return
    elif not os.path.exists(policy_path):
        print(f"❌ Policy file not found: {policy_path}")
        return
        
    if not args.quiet:
        print("🔒 Email Security Scanner")
        print(f"📧 Email: {args.email}")
        print(f"� Policy: {policy_path}")
        print("-" * 50)
    
    # Evaluate policy
    result = evaluate_policy_for_eml(
        args.email,
        policy_path,
        quiet=args.quiet
    )
    
    # Show results
    matches = result.get("matches", [])
    if matches:
        print(f"🚨 Found {len(matches)} policy matches")
        for rule_id, action, reason in matches:
            print(f"- Rule {rule_id}: {action.upper()} ({reason})")
        
        final_action = result.get("final_action", "none")
        final_rule = result.get("final_rule")
        final_reason = result.get("final_reason")
        print(f"\n🔥 Final Action: {final_action.upper()}")
        if final_rule:
            print(f"📝 Rule: {final_rule}")
        if final_reason:
            print(f"💡 Reason: {final_reason}")
    else:
        print("✅ No policy matches - email passes all rules")

# ========== RUN PROGRAM ==========
if __name__ == "__main__":
    main()
