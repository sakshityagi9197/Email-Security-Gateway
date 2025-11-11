import os
from pathlib import Path
from email import message_from_bytes
from bs4 import BeautifulSoup
import hashlib

# ========== Task 1: Parse Headers ==========
def parse_email_headers(msg):
    return {
        'From': msg.get('From'),
        'To': msg.get('To'),
        'Subject': msg.get('Subject'),
        'Date': msg.get('Date'),
        'Message-ID': msg.get('Message-ID'),
        'Return-Path': msg.get('Return-Path'),
        'Received': msg.get('Received')
    }

# ========== Task 2: Extract Plain and HTML Body ==========
def extract_email_bodies(msg):
    plain_body = ''
    html_body = ''
    for part in msg.walk():
        content_type = part.get_content_type()
        if content_type == 'text/plain' and not plain_body:
            plain_body = part.get_payload(decode=True).decode(errors='replace')
        elif content_type == 'text/html' and not html_body:
            html_body = part.get_payload(decode=True).decode(errors='replace')
    return {'plain': plain_body, 'html': html_body}

# ========== Task 3: Extract Hyperlinks ==========
def extract_hyperlinks(html_body):
    soup = BeautifulSoup(html_body, 'html.parser')
    return [a['href'] for a in soup.find_all('a', href=True)]

# ========== Task 4: Compute SHA256 Hash ==========
def compute_sha256_hash(plain_body):
    return hashlib.sha256(plain_body.encode()).hexdigest()

# ========== Task 5: Extract Attachment Metadata ==========
def extract_attachment_metadata(msg):
    attachments = []
    for part in msg.walk():
        if part.get_content_disposition() == 'attachment':
            attachments.append({
                'filename': part.get_filename(),
                'content_type': part.get_content_type(),
                'size': len(part.get_payload(decode=True))
            })
    return attachments

# ========== MAIN SCRIPT ==========
def process_unthreat_folder():
    folder = Path("storage/unthreat")
    if not folder.exists():
        print("⚠️ Folder 'storage/unthreat/' does not exist.")
        return

    eml_files = list(folder.glob("*.eml"))
    if not eml_files:
        print("⚠️ No .eml files found in 'unthreat/'.")
        return

    for file in eml_files:
        print("\n📂 Processing:", file.name)
        with open(file, 'rb') as f:
            eml_content = f.read()

        # Parse the .eml message
        msg = message_from_bytes(eml_content)

        # Task 1
        headers = parse_email_headers(msg)
        print("📨 Headers:", headers)

        # Task 2
        bodies = extract_email_bodies(msg)

        # Task 3
        links = extract_hyperlinks(bodies['html']) if bodies['html'] else []
        print("🔗 Hyperlinks:", links)

        # Task 4
        body_hash = compute_sha256_hash(bodies['plain']) if bodies['plain'] else None
        print("🔐 Body SHA256:", body_hash)

        # Task 5
        attachments = extract_attachment_metadata(msg)
        print("📎 Attachments:", attachments)

# Run the parser
if __name__ == "__main__":
    process_unthreat_folder()
