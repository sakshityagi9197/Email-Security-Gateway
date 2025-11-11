#!/usr/bin/env python3
"""
Simple DMARC Verifier
Verifies DMARC policy compliance for email content
"""

import email
import dns.resolver
import re
from email.utils import parseaddr
from urllib.parse import unquote

def get_dmarc_record(domain):
    """
    Retrieve DMARC record for a domain.
    
    Args:
        domain: Domain to check
        
    Returns:
        str: DMARC record or None if not found
    """
    try:
        # DMARC records are stored at _dmarc.domain.com
        dmarc_domain = f"_dmarc.{domain}"
        txt_records = dns.resolver.resolve(dmarc_domain, 'TXT')
        
        for record in txt_records:
            txt_data = ''.join([s.decode() if isinstance(s, bytes) else s for s in record.strings])
            if txt_data.startswith('v=DMARC1'):
                return txt_data
        
        return None
    except Exception as e:
        return None

def parse_dmarc_record(dmarc_record):
    """
    Parse DMARC record into a dictionary.
    
    Args:
        dmarc_record: DMARC TXT record string
        
    Returns:
        dict: Parsed DMARC policy parameters
    """
    if not dmarc_record:
        return {}
    
    params = {}
    # Split by semicolon and parse key=value pairs
    for param in dmarc_record.split(';'):
        param = param.strip()
        if '=' in param:
            key, value = param.split('=', 1)
            params[key.strip().lower()] = value.strip()
    
    return params

def validate_dmarc(raw_email, dkim_result, spf_results):
    """
    Validate DMARC policy compliance with provided DKIM and SPF results.
    
    Args:
        raw_email: Raw email content (string or bytes)
        dkim_result: DKIM verification result (True/False)
        spf_results: List of SPF results - each should be (ip, is_valid, result_code, message)
                    or single tuple (is_valid, result_code, message) for backwards compatibility
        
    Returns:
        tuple: (is_compliant, policy_result, dmarc_policy, message)
    """
    try:
        # Ensure raw_email is string
        if isinstance(raw_email, bytes):
            email_str = raw_email.decode('utf-8', errors='replace')
        else:
            email_str = raw_email
        
        # Parse email
        msg = email.message_from_string(email_str)
        
        # Get From header domain (Header From)
        from_header = msg.get('From')
        if not from_header:
            return False, 'none', {}, "No From header found"
        
        _, from_email = parseaddr(from_header)
        if '@' not in from_email:
            return False, 'none', {}, f"Invalid From address: {from_email}"
        
        from_domain = from_email.split('@')[1].lower()
        
        # Get DMARC record for the domain
        dmarc_record = get_dmarc_record(from_domain)
        if not dmarc_record:
            return False, 'none', {}, f"No DMARC record found for {from_domain}"
        
        # Parse DMARC policy
        dmarc_policy = parse_dmarc_record(dmarc_record)
        policy_action = dmarc_policy.get('p', 'none').lower()
        
        # Process SPF results - check if any SPF check passed
        spf_passed = False
        if isinstance(spf_results, list):
            # Handle list of SPF results for multiple IPs
            for spf_result in spf_results:
                if len(spf_result) >= 3:  # (ip, is_valid, result_code, message) or (is_valid, result_code, message)
                    if len(spf_result) == 4:
                        _, is_valid, result_code, _ = spf_result
                    else:
                        is_valid, result_code, _ = spf_result
                    
                    if is_valid and result_code == 'pass':
                        spf_passed = True
                        break
        elif isinstance(spf_results, tuple) and len(spf_results) >= 2:
            # Handle single SPF result tuple
            if len(spf_results) == 4:
                _, is_valid, result_code, _ = spf_results
            else:
                is_valid, result_code, _ = spf_results
            spf_passed = is_valid and result_code == 'pass'
        
        # Check identifier alignment
        dkim_aligned = check_dkim_alignment(msg, from_domain, dmarc_policy, dkim_result)
        spf_aligned = check_spf_alignment(msg, from_domain, dmarc_policy, spf_passed, None)
        
        # DMARC passes if either DKIM or SPF is aligned and passes
        dmarc_pass = (dkim_aligned and dkim_result) or (spf_aligned and spf_passed)
        
        # Build detailed message with correct logic
        auth_details = []
        
        # DKIM reporting
        if dkim_result and dkim_aligned:
            auth_details.append("DKIM: passed and aligned")
        elif dkim_result and not dkim_aligned:
            auth_details.append("DKIM: passed but not aligned")
        else:
            auth_details.append("DKIM: failed")
        
        # SPF reporting  
        if spf_passed and spf_aligned:
            auth_details.append("SPF: passed and aligned")
        elif spf_passed and not spf_aligned:
            auth_details.append("SPF: passed but not aligned")
        else:
            auth_details.append("SPF: failed")
        
        # Determine policy result
        if dmarc_pass:
            policy_result = 'pass'
            is_compliant = True
            message = f"DMARC check passed for {from_domain} ({', '.join(auth_details)})"
        else:
            policy_result = 'fail'
            is_compliant = False
            message = f"DMARC check failed for {from_domain}. Policy: {policy_action} ({', '.join(auth_details)})"
        
        return is_compliant, policy_result, dmarc_policy, message
        
    except Exception as e:
        return False, 'error', {}, f"Error during DMARC validation: {e}"

def check_dkim_alignment(msg, from_domain, dmarc_policy, dkim_result):
    """Check if DKIM signature is aligned with From domain."""
    # DKIM must pass first before checking alignment
    if not dkim_result:
        return False
    
    try:
        # Get DKIM signature header
        dkim_sig = msg.get('DKIM-Signature')
        if not dkim_sig:
            return False
        
        # Parse DKIM signature to get domain (d= parameter)
        dkim_domain_match = re.search(r'd=([^;\s]+)', dkim_sig)
        if not dkim_domain_match:
            return False
        
        dkim_domain = dkim_domain_match.group(1).strip().lower()
        
        # Check alignment based on DMARC policy
        alignment_mode = dmarc_policy.get('adkim', 'r').lower()  # relaxed by default
        
        if alignment_mode == 's':  # strict alignment
            return dkim_domain == from_domain
        else:  # relaxed alignment
            return dkim_domain == from_domain or dkim_domain.endswith('.' + from_domain) or from_domain.endswith('.' + dkim_domain)
    
    except Exception:
        return False

def check_spf_alignment(msg, from_domain, dmarc_policy, spf_result, sender_ip):
    """Check if SPF is aligned with From domain."""
    # SPF must pass first before checking alignment
    if not spf_result:
        return False
    
    try:
        # Get envelope sender domain (Return-Path or From)
        envelope_sender = None
        return_path = msg.get('Return-Path')
        if return_path:
            envelope_sender = return_path.strip('<>')
        else:
            from_header = msg.get('From')
            if from_header:
                _, envelope_sender = parseaddr(from_header)
        
        if not envelope_sender or '@' not in envelope_sender:
            return False
        
        envelope_domain = envelope_sender.split('@')[1].lower()
        
        # Check alignment based on DMARC policy
        alignment_mode = dmarc_policy.get('aspf', 'r').lower()  # relaxed by default
        
        if alignment_mode == 's':  # strict alignment
            return envelope_domain == from_domain
        else:  # relaxed alignment
            return envelope_domain == from_domain or envelope_domain.endswith('.' + from_domain) or from_domain.endswith('.' + envelope_domain)
    
    except Exception:
        return False

def verify_dmarc_simple(from_domain, dkim_result=None, spf_result=None, dkim_domain=None, envelope_domain=None):
    """
    Simple DMARC verification with just domain and auth results.
    
    Args:
        from_domain: Domain from From header
        dkim_result: DKIM verification result (True/False)
        spf_result: SPF verification result (True/False)
        dkim_domain: Domain from DKIM signature (for alignment check)
        envelope_domain: Domain from envelope sender (for alignment check)
        
    Returns:
        tuple: (is_compliant, policy_result, dmarc_policy, message)
    """
    try:
        # Get DMARC record
        dmarc_record = get_dmarc_record(from_domain)
        if not dmarc_record:
            return False, 'none', {}, f"No DMARC record found for {from_domain}"
        
        # Parse DMARC policy
        dmarc_policy = parse_dmarc_record(dmarc_record)
        policy_action = dmarc_policy.get('p', 'none').lower()
        
        # Check alignment
        dkim_aligned = False
        spf_aligned = False
        
        if dkim_result and dkim_domain:
            alignment_mode = dmarc_policy.get('adkim', 'r').lower()
            if alignment_mode == 's':
                dkim_aligned = dkim_domain.lower() == from_domain.lower()
            else:
                dkim_aligned = (dkim_domain.lower() == from_domain.lower() or 
                              dkim_domain.lower().endswith('.' + from_domain.lower()) or
                              from_domain.lower().endswith('.' + dkim_domain.lower()))
        
        if spf_result and envelope_domain:
            alignment_mode = dmarc_policy.get('aspf', 'r').lower()
            if alignment_mode == 's':
                spf_aligned = envelope_domain.lower() == from_domain.lower()
            else:
                spf_aligned = (envelope_domain.lower() == from_domain.lower() or 
                             envelope_domain.lower().endswith('.' + from_domain.lower()) or
                             from_domain.lower().endswith('.' + envelope_domain.lower()))
        
        # DMARC passes if either DKIM or SPF is aligned and passes
        dmarc_pass = (dkim_aligned and dkim_result) or (spf_aligned and spf_result)
        
        if dmarc_pass:
            return True, 'pass', dmarc_policy, f"DMARC check passed for {from_domain}"
        else:
            return False, 'fail', dmarc_policy, f"DMARC check failed for {from_domain}. Policy: {policy_action}"
        
    except Exception as e:
        return False, 'error', {}, f"Error during DMARC verification: {e}"

def interpret_dmarc_policy(dmarc_policy):
    """
    Interpret DMARC policy parameters.
    
    Args:
        dmarc_policy: Parsed DMARC policy dictionary
        
    Returns:
        str: Human-readable policy explanation
    """
    if not dmarc_policy:
        return "No DMARC policy found"
    
    policy = dmarc_policy.get('p', 'none')
    subdomain_policy = dmarc_policy.get('sp', policy)
    alignment_dkim = dmarc_policy.get('adkim', 'r')
    alignment_spf = dmarc_policy.get('aspf', 'r')
    percentage = dmarc_policy.get('pct', '100')
    
    explanation = f"DMARC Policy: {policy}"
    explanation += f", Subdomain Policy: {subdomain_policy}"
    explanation += f", DKIM Alignment: {'strict' if alignment_dkim == 's' else 'relaxed'}"
    explanation += f", SPF Alignment: {'strict' if alignment_spf == 's' else 'relaxed'}"
    explanation += f", Percentage: {percentage}%"
    
    if 'rua' in dmarc_policy:
        explanation += f", Aggregate Reports: {dmarc_policy['rua']}"
    
    if 'ruf' in dmarc_policy:
        explanation += f", Forensic Reports: {dmarc_policy['ruf']}"
    
    return explanation

def main():
    """Example usage - for demonstration purposes."""
    import sys
    
    print("This script is designed to be used as a library.")
    print("Example usage:")
    print()
    print("import dmarc_verifier")
    print()
    print("# DKIM result example")
    print("dkim_result = True  # or False")
    print()
    print("# SPF results example (multiple IPs)")
    print("spf_results = [")
    print("    ('025.06.17.21', False, 'error', 'Invalid IP address'),")
    print("    ('2002:a17:504:8003:b0:1ce1:971e:9c39', False, 'fail', 'SPF fail - not authorized'),")
    print("    ('76.223.180.106', True, 'pass', 'sender SPF authorized')")
    print("]")
    print()
    print("# Validate DMARC")
    print("result, code, policy, message = dmarc_verifier.validate_dmarc(raw_email, dkim_result, spf_results)")
    print()
    
    if len(sys.argv) >= 2:
        domain = sys.argv[1]
        print(f"Testing DMARC policy for domain: {domain}")
        print("-" * 50)
        
        # Get and display DMARC record
        dmarc_record = get_dmarc_record(domain)
        if dmarc_record:
            print(f"DMARC Record: {dmarc_record}")
            dmarc_policy = parse_dmarc_record(dmarc_record)
            print(f"Policy Interpretation: {interpret_dmarc_policy(dmarc_policy)}")
        else:
            print(f"No DMARC record found for {domain}")
    
    print()
    print("Sample validation with your provided results:")
    print("-" * 50)
    
    # Sample raw email
    sample_email = """From: sender@example.com
To: recipient@example.com  
Subject: Test Email

Hello World!
"""
    
    # Your provided results
    dkim_result = True
    spf_results = [
        ('025.06.17.21', False, 'error', "Error during SPF verification: '025.06.17.21' does not appear to be an IPv4 or IPv6 address"),
        ('2002:a17:504:8003:b0:1ce1:971e:9c39', False, 'fail', 'SPF fail - not authorized'),
        ('76.223.180.106', True, 'pass', 'sender SPF authorized')
    ]
    
    is_compliant, result_code, policy, message = validate_dmarc(sample_email, dkim_result, spf_results)
    
    print(f"DKIM Result: {dkim_result}")
    print("SPF Results:")
    for ip, valid, code, msg in spf_results:
        print(f"  IP {ip}: Valid={valid}, Result={code}")
    
    print(f"\nDMARC Validation:")
    print(f"Compliant: {is_compliant}")
    print(f"Result: {result_code}")
    print(f"Message: {message}")
    if policy:
        print(f"Policy: {interpret_dmarc_policy(policy)}")

if __name__ == "__main__":
    main()