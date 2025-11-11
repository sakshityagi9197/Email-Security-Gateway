import dkim

def verify_dkim_with_header(raw_email, dkim_signature_header):
    """Verify DKIM signature by replacing the header in raw email content."""
    try:
        # Ensure raw_email is bytes
        if isinstance(raw_email, str):
            email_bytes = raw_email.encode('utf-8')
        else:
            email_bytes = raw_email
        
        # Convert to string to replace DKIM header
        email_str = email_bytes.decode('utf-8', errors='replace')
        
        # Simple replacement: find first occurrence of DKIM-Signature and replace
        lines = email_str.split('\n')
        new_lines = []
        dkim_replaced = False
        skip_continuation = False
        
        for line in lines:
            if line.lower().startswith('dkim-signature:') and not dkim_replaced:
                new_lines.append(f"DKIM-Signature: {dkim_signature_header}")
                dkim_replaced = True
                skip_continuation = True
            elif skip_continuation and (line.startswith(' ') or line.startswith('\t')):
                # Skip DKIM continuation lines
                continue
            elif line == '' or not (line.startswith(' ') or line.startswith('\t')):
                skip_continuation = False
                new_lines.append(line)
            else:
                new_lines.append(line)
        
        # If no DKIM signature was found, add it at the beginning
        if not dkim_replaced:
            new_lines.insert(0, f"DKIM-Signature: {dkim_signature_header}")
        
        # Convert back to bytes
        modified_email = '\n'.join(new_lines).encode('utf-8')
        
        # Use dkimpy to verify
        result = dkim.verify(modified_email)
        
        if result:
            return True, "DKIM signature verified successfully"
        else:
            return False, "DKIM signature verification failed"
            
    except Exception as e:
        return False, f"Error: {e}"

def verify_existing_dkim(raw_email):
    """Verify existing DKIM signatures in the raw email content."""
    try:
        # Ensure raw_email is bytes
        if isinstance(raw_email, str):
            email_bytes = raw_email.encode('utf-8')
        else:
            email_bytes = raw_email
            
        # Check if email has DKIM-Signature header
        email_str = email_bytes.decode('utf-8', errors='replace')
        has_dkim = False
        for line in email_str.split('\n'):
            if line.lower().startswith('dkim-signature:'):
                has_dkim = True
                break
                
        if not has_dkim:
            return False, "Missing DKIM signature"
            
        # Try to verify, but if anything goes wrong just mark as failed
        try:
            result = dkim.verify(email_bytes)
            if result:
                return True, "DKIM signature verified successfully"
        except:
            pass
            
        return False, "DKIM verification failed"
            
    except Exception:
        return False, "DKIM verification failed"

def main():
    """Example usage - for demonstration purposes."""
    import sys
    
    if len(sys.argv) < 2:
        print("This script is designed to be used as a library.")
        print("Example usage:")
        print()
        print("import dkim_verifier")
        print()
        print("# Verify existing DKIM signatures")
        print("result, message = dkim_verifier.verify_existing_dkim(raw_email_content)")
        print()
        print("# Verify with custom DKIM header") 
        print("result, message = dkim_verifier.verify_dkim_with_header(raw_email_content, dkim_header)")
        print()
        print("For file-based testing, provide file path:")
        print("python dkim_verifier.py <eml_file> [dkim_header]")
        return
    
    # File-based testing for convenience
    eml_file = sys.argv[1]
    
    try:
        with open(eml_file, 'rb') as f:
            raw_email = f.read()
    except Exception as e:
        print(f"Error reading file: {e}")
        return
    
    print(f"Testing DKIM verification for: {eml_file}")
    print("-" * 50)
    
    if len(sys.argv) == 2:
        # Verify existing DKIM signatures
        is_valid, message = verify_existing_dkim(raw_email)
    else:
        # Verify with provided DKIM header
        dkim_header = sys.argv[2]
        is_valid, message = verify_dkim_with_header(raw_email, dkim_header)
    
    if is_valid:
        print("✓ DKIM Verification: PASSED")
    else:
        print("✗ DKIM Verification: FAILED")
    
    print(f"Details: {message}")

if __name__ == "__main__":
    main()