import spf
import email
import re
from email.utils import parseaddr

def verify_spf(raw_email, sender_ip, helo_domain=None):
    """
    Verify SPF for raw email content.
    
    Args:
        raw_email: Raw email content (string or bytes)
        sender_ip: IP address of the sending server
        helo_domain: HELO/EHLO domain (optional, will try to extract from headers)
    
    Returns:
        tuple: (is_valid, result_code, message)
    """
    try:
        # Ensure raw_email is string
        if isinstance(raw_email, bytes):
            email_str = raw_email.decode('utf-8', errors='replace')
        else:
            email_str = raw_email
        
        # Parse email to extract sender information
        msg = email.message_from_string(email_str)
        
        # Get the envelope sender (Return-Path or From)
        envelope_sender = None
        return_path = msg.get('Return-Path')
        if return_path:
            # Clean up Return-Path (remove < >)
            envelope_sender = return_path.strip('<>')
        else:
            # Fallback to From header
            from_header = msg.get('From')
            if from_header:
                _, envelope_sender = parseaddr(from_header)
        
        if not envelope_sender:
            return False, 'none', "No sender address found in email"
        
        # Extract domain from sender email
        if '@' not in envelope_sender:
            return False, 'none', f"Invalid sender address: {envelope_sender}"
        
        sender_domain = envelope_sender.split('@')[1]
        
        # Use provided HELO domain or try to extract from Received headers
        if not helo_domain:
            helo_domain = extract_helo_domain(msg)
        
        # Perform SPF check using pyspf
        result, explanation = spf.check2(
            i=sender_ip,
            s=envelope_sender,
            h=helo_domain or sender_domain
        )
        
        # Map SPF results to success/failure
        success_results = ['pass']
        is_valid = result in success_results
        
        return is_valid, result, explanation
        
    except Exception as e:
        return False, 'error', f"Error during SPF verification: {e}"

def verify_spf_simple(sender_email, sender_ip, helo_domain=None):
    """
    Simple SPF verification with just sender email and IP.
    
    Args:
        sender_email: Sender's email address
        sender_ip: IP address of the sending server
        helo_domain: HELO/EHLO domain (optional)
    
    Returns:
        tuple: (is_valid, result_code, message)
    """
    try:
        if '@' not in sender_email:
            return False, 'none', f"Invalid sender email: {sender_email}"
        
        sender_domain = sender_email.split('@')[1]
        
        # Perform SPF check using pyspf
        result, explanation = spf.check2(
            i=sender_ip,
            s=sender_email,
            h=helo_domain or sender_domain
        )
        
        # Map SPF results to success/failure
        success_results = ['pass']
        is_valid = result in success_results
        
        return is_valid, result, explanation
        
    except Exception as e:
        return False, 'error', f"Error during SPF verification: {e}"

def extract_helo_domain(msg):
    """Extract HELO/EHLO domain from Received headers."""
    try:
        received_headers = msg.get_all('Received') or []
        for received in received_headers:
            # Look for HELO/EHLO in received headers
            # Pattern: "from domain.com (HELO helo.domain.com)"
            helo_match = re.search(r'\((?:HELO|EHLO)\s+([^\s\)]+)\)', received, re.IGNORECASE)
            if helo_match:
                return helo_match.group(1)
            
            # Alternative pattern: "from [IP] (helo=domain.com)"
            helo_match = re.search(r'helo=([^\s\)]+)', received, re.IGNORECASE)
            if helo_match:
                return helo_match.group(1)
        
        return None
    except Exception:
        return None

def get_spf_record(domain):
    """
    Retrieve SPF record for a domain.
    
    Args:
        domain: Domain to check
        
    Returns:
        str: SPF record or None if not found
    """
    try:
        result = spf.check2(i='127.0.0.1', s=f'test@{domain}', h=domain)
        # This is a hacky way to get SPF record, better to use DNS library
        import dns.resolver
        try:
            txt_records = dns.resolver.resolve(domain, 'TXT')
            for record in txt_records:
                txt_data = ''.join([s.decode() if isinstance(s, bytes) else s for s in record.strings])
                if txt_data.startswith('v=spf1'):
                    return txt_data
        except:
            pass
        return None
    except Exception:
        return None

def interpret_spf_result(result_code):
    """
    Interpret SPF result codes.
    
    Args:
        result_code: SPF result code
        
    Returns:
        str: Human-readable explanation
    """
    interpretations = {
        'pass': 'SPF check passed - sender is authorized',
        'fail': 'SPF check failed - sender is not authorized',
        'softfail': 'SPF soft fail - sender might not be authorized',
        'neutral': 'SPF neutral - no assertion about sender',
        'none': 'No SPF record found for domain',
        'temperror': 'Temporary DNS error during SPF check',
        'permerror': 'Permanent error in SPF record',
        'error': 'Error during SPF verification'
    }
    return interpretations.get(result_code, f'Unknown result: {result_code}')

def main():
    """Example usage - for demonstration purposes."""
    import sys
    
    if len(sys.argv) < 3:
        print("This script is designed to be used as a library.")
        print("Example usage:")
        print()
        print("import spf_verifier")
        print()
        print("# Verify SPF from raw email")
        print("result, code, message = spf_verifier.verify_spf(raw_email, sender_ip)")
        print()
        print("# Simple SPF verification")
        print("result, code, message = spf_verifier.verify_spf_simple(sender_email, sender_ip)")
        print()
        print("For testing, provide parameters:")
        print("python spf_verifier.py <sender_email> <sender_ip> [helo_domain]")
        print("python spf_verifier.py sender@example.com 192.168.1.1 mail.example.com")
        return
    
    # Command line testing
    sender_email = sys.argv[1]
    sender_ip = sys.argv[2]
    helo_domain = sys.argv[3] if len(sys.argv) > 3 else None
    
    print(f"Testing SPF verification for:")
    print(f"Sender: {sender_email}")
    print(f"IP: {sender_ip}")
    print(f"HELO: {helo_domain or 'Not provided'}")
    print("-" * 50)
    
    is_valid, result_code, message = verify_spf_simple(sender_email, sender_ip, helo_domain)
    
    if is_valid:
        print("✓ SPF Verification: PASSED")
    else:
        print("✗ SPF Verification: FAILED")
    
    print(f"Result Code: {result_code}")
    print(f"Details: {message}")
    print(f"Explanation: {interpret_spf_result(result_code)}")

if __name__ == "__main__":
    main()