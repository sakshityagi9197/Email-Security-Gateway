import base64
import datetime
import json
import traceback
import os
import eml_parser

from backend.schemas.class_schema import EmailMessage
from backend.schemas.class_schema import EmailBody

from typing import List, Tuple  # Added Tuple import

def json_serial(obj):
    """JSON serializer for objects not serializable by default json code."""
    if isinstance(obj, (datetime.datetime, datetime.date)):
        return obj.isoformat()
    if isinstance(obj, (bytes, bytearray, memoryview)):
        try:
            return base64.b64encode(bytes(obj)).decode("ascii")
        except Exception:
            return str(obj)
    if isinstance(obj, (set, tuple)):
        return list(obj)
    return str(obj)

def parse_eml(raw_email: bytes):
    """Parses raw EML bytes using eml_parser and returns JSON-safe dict."""
    try:
        try:
            ep = eml_parser.EmlParser(include_raw_body=True, include_attachment_data=True)
        except TypeError:
            ep = eml_parser.EmlParser()
        parsed_eml = ep.decode_email_bytes(raw_email)
        return json.loads(json.dumps(parsed_eml, default=json_serial))
    except Exception as e:
        print("❌ Failed to parse EML file:")
        traceback.print_exc()
        raise

def process_email_attachments(raw_email: bytes, save_path: str) -> List[Tuple[str, str]]:
    """
    Processes raw EML bytes to extract and save attachments in one step.
    """
    saved_files = []
    try:
        ep = eml_parser.EmlParser()
        parsed_eml = ep.decode_email_bytes(raw_email)
        eml_json = json.loads(json.dumps(parsed_eml, default=json_serial))
        os.makedirs(save_path, exist_ok=True)
        if 'attachment' not in eml_json:
            return saved_files
        for attachment in eml_json['attachment']:
            filename = attachment.get('filename', 'unnamed_attachment')
            content = attachment.get('raw_content')
            if content:
                full_save_path = os.path.join(save_path, filename)
                try:
                    decoded_content = base64.b64decode(content)
                    with open(full_save_path, 'wb') as f:
                        f.write(decoded_content)
                    saved_files.append((filename, full_save_path))
                except Exception as e:
                    print(f"❌ Failed to save attachment {filename}: {str(e)}")
                    continue
        return saved_files
    except Exception as e:
        print("❌ Failed to process email attachments:")
        traceback.print_exc()
        return saved_files

def extract_attachments(eml_json: dict, save_path: str) -> List[Tuple[str, str]]:
    """
    Extracts attachments from parsed EML JSON and saves them to specified path.
    """
    saved_files = []
    os.makedirs(save_path, exist_ok=True)
    if 'attachment' not in eml_json:
        return saved_files
    for attachment in eml_json['attachment']:
        filename = attachment.get('filename', 'unnamed_attachment')
        content = (
            attachment.get('raw_content')
            or attachment.get('raw')
            or attachment.get('payload')
            or attachment.get('data')
            or attachment.get('content')
        )
        if content:
            full_save_path = os.path.join(save_path, filename)
            try:
                if isinstance(content, (bytes, bytearray)):
                    decoded_content = bytes(content)
                else:
                    decoded_content = base64.b64decode(content)
                with open(full_save_path, 'wb') as f:
                    f.write(decoded_content)
                saved_files.append((filename, full_save_path))
            except Exception as e:
                print(f"❌ Failed to save attachment {filename}: {str(e)}")
                continue
    return saved_files

if __name__ == "__main__":
    from backend.ingestion.ingestion import load_email
    raw_email = load_email(r"../samples/Your_Tickets.eml")
    save_directory = "../extracted_attachments"
    eml_json = parse_eml(raw_email)
    ob = EmailMessage()
    ob.load_eml_data(eml_json)
    ob.print_eml_details()
    saved_attachments = process_email_attachments(raw_email, save_directory)
    for filename, path in saved_attachments:
        print(f"Saved attachment: {filename} at {path}")