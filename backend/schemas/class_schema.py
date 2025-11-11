# email_schema.py
from typing import List
from backend.schemas.attachment_schema import AttachmentInfo
from backend.schemas.body_schema import EmailBody


class EmailMessage:
    def __init__(self, headers=None, body=None, attachments=None, metadata=None):
        self.date = None
        self.headers = headers or {}
        self.body = body or {}
        self.body_objects: List[EmailBody] = []
        self.attachments = attachments or []
        self.attachment_objects = []
        self.metadata = metadata or {}
        self.raw_eml_file: bytes   # Add this line to store raw email body
        self.eml_file_path= None  # Add this line to store the EML file path
        self.dkim_check = None  # Add this line to store DKIM check result
        self.spf_check= None  # Add this line to store SPF check result
        self.dmarc_check = None  # Add this line to store DMARC check result
        self.received_ips: List[str] = []


        # Basic email details
        self.message_id = None
        self.subject = None
        self.date = None
        self.email_from = None
        self.email_to = []
        self.delivered_to = []


        # Authentication & metadata
        self.authentication_results = None
        self.arc_authentication_results = None
        self.dkim_signature = []
        self.arc_seal = None
        self.arc_message_signature = None
        self.received_spf = None
        self.return_path = None
        self.feedback_id = None

        # MIME & Content
        self.mime_version = None
        self.content_type = None
        self.x_mailer = None

        # X-Headers
        self.x_google_smtp_source = None
        self.x_ses_outgoing = None
        self.x_received = None

        # Received hops (parsed from 'received' headers)
        self.hops_from = []
        self.hops_by = []
        self.hops_with = []
        self.hops_date = []
        self.hops_delay = []  # (optional: if you want to calculate delay between hops later)

        # Attachments (assumed to be in eml_json['attachments'])
        # self.attachments = None

    def DisplayEmailData(self):
        print("Email Data")

    def load_eml_data(self, eml_json, file_path=None):
        try:
            # Flatten header block
            self.eml_file_path = file_path
            header = eml_json.get('header', {})
            # Load received IPs
            self.received_ips = header.get('received_ip', [])
            if 'header' in header:
                header = header['header']

            def safe_get(key, default=None):
                value = header.get(key, default)
                return value[0] if isinstance(value, list) and value else value

            

            # Load email details
            self.message_id = safe_get('message-id')
            self.subject = safe_get('subject')
            self.date = safe_get('date')
            self.email_from = safe_get('from')
            self.email_to = header.get('to', [])
            self.delivered_to = header.get('delivered-to', [])

            # Authentication
            self.authentication_results = safe_get('authentication-results')
            self.arc_authentication_results = safe_get('arc-authentication-results')
            self.dkim_signature = header.get('dkim-signature', [])
            self.arc_seal = safe_get('arc-seal')
            self.arc_message_signature = safe_get('arc-message-signature')
            self.received_spf = safe_get('received-spf')
            self.return_path = safe_get('return-path')
            self.feedback_id = safe_get('feedback-id')

            # MIME
            self.content_type = safe_get('content-type')
            self.mime_version = safe_get('mime-version')
            self.x_mailer = safe_get('x-mailer')

            # X-Headers
            self.x_google_smtp_source = safe_get('x-google-smtp-source')
            self.x_ses_outgoing = safe_get('x-ses-outgoing')
            self.x_received = safe_get('x-received')

            # Load body content

            # Received hops
            self.hops_from = []
            self.hops_by = []
            self.hops_with = []
            self.hops_date = []

            for hop in eml_json.get('received', []):
                self.hops_from.append(hop.get('from', ''))
                self.hops_by.append(hop.get('by', ''))
                self.hops_with.append(hop.get('with', ''))
                self.hops_date.append(hop.get('date', ''))

            # Attachments
            self.attachment_objects = []
            for attachment in eml_json.get('attachment', []):
                hash_block = attachment.get("hash", {})
                content_header = attachment.get("content_header", {})

                self.attachment_objects.append(AttachmentInfo(
                    filename=attachment.get("filename"),
                    size=attachment.get("size"),
                    extension=attachment.get("extension"),
                    hash_md5=hash_block.get("md5"),
                    hash_sha1=hash_block.get("sha1"),
                    hash_sha256=hash_block.get("sha256"),
                    hash_sha512=hash_block.get("sha512"),
                    content_type=content_header.get("content-type"),
                    content_disposition=content_header.get("content-disposition"),
                    content_transfer_encoding=content_header.get("content-transfer-encoding")
                ))

            # Body
            self.body_objects = []
            for body_part in eml_json.get('body', []):
                content_header = body_part.get("content_header", {})
                self.body_objects.append(EmailBody(
                    uri_hash=body_part.get("uri_hash", []),
                    domain_hash=body_part.get("domain_hash", []),
                    content_type=body_part.get("content_type"),
                    hash=body_part.get("hash"),
                    boundary=body_part.get("boundary"),
                    content_header_content_type=content_header.get("content-type", []),
                    content_header_content_transfer_encoding=content_header.get("content-transfer-encoding", [])
                ))

        except Exception as e:
            print("❌ Failed to load email data.")
            import traceback
            traceback.print_exc()

    def print_eml_details(self):
        try:
            print("\n" + "=" * 60)
            print("📧 COMPLETE EMAIL DETAILS".center(60))
            print("=" * 60)

            print(f"{'Subject':25}: {self.subject}")
            print(f"{'Message ID':25}: {self.message_id}")
            print(f"{'Date':25}: {self.date}")
            print(f"{'From':25}: {self.email_from}")
            print(f"{'To':25}: {', '.join(self.email_to) if self.email_to else 'None'}")
            print(f"{'Delivered To':25}: {', '.join(self.delivered_to) if self.delivered_to else 'None'}")

            print(f"{'SPF':25}: {self.received_spf}")
            print(f"{'DKIM Signature':25}: {self.dkim_signature if self.dkim_signature else 'None'}")
            print(f"{'ARC Seal':25}: {self.arc_seal}")
            print(f"{'ARC Msg Signature':25}: {self.arc_message_signature}")
            print(f"{'Authentication Results':25}: {self.authentication_results}")
            print(f"{'ARC Auth Results':25}: {self.arc_authentication_results}")
            print(f"{'Return Path':25}: {self.return_path}")
            print(f"{'Feedback ID':25}: {self.feedback_id}")
            print(f"{'MIME Version':25}: {self.mime_version}")
            print(f"{'Content Type':25}: {self.content_type}")
            print(f"{'X-Mailer':25}: {self.x_mailer}")
            print(f"{'X-Google SMTP':25}: {self.x_google_smtp_source}")
            print(f"{'X-SES Outgoing':25}: {self.x_ses_outgoing}")
            print(f"{'X-Received':25}: {self.x_received}")

            print("\n" + "-" * 60)
            print("📡 RECEIVED HOPS")
            print("-" * 60)
            for i, (f, b, w, d) in enumerate(zip(self.hops_from, self.hops_by, self.hops_with, self.hops_date), 1):
                print(f"Hop {i:02}: From={f}, By={b}, With={w}, Date={d}")

            print("\n" + "-" * 60)
            print("📎 ATTACHMENTS")
            print("-" * 60)
            for i, att in enumerate(self.attachment_objects, 1):
                print(f"\nAttachment {i}:")
                print(f"  Filename         : {att.filename}")
                print(f"  Size             : {att.size}")
                print(f"  Extension        : {att.extension}")
                print(f"  MD5              : {att.hash_md5}")
                print(f"  SHA1             : {att.hash_sha1}")
                print(f"  SHA256           : {att.hash_sha256}")
                print(f"  SHA512           : {att.hash_sha512}")
                print(f"  Content-Type     : {att.content_type}")
                print(f"  Content-Disposition: {att.content_disposition}")
                print(f"  Transfer-Encoding: {att.content_transfer_encoding}")

            print("\n" + "-" * 60)
            print("📝 BODY PARTS")
            print("-" * 60)
            for i, body in enumerate(self.body_objects, 1):
                print(f"\nBody Part {i}:")
                print(f"  Content-Type     : {body.content_type}")
                print(f"  Hash             : {body.hash}")
                print(f"  Boundary         : {body.boundary}")
                print(f"  URI Hashes       : {len(body.uri_hash)} entries")
                print(f"  Domain Hashes    : {len(body.domain_hash)} entries")
                print(f"  Header: content-type: {body.content_header_content_type}")
                print(f"  Header: encoding : {body.content_header_content_transfer_encoding}")

            print("\n" + "=" * 60 + "\n")

        except Exception as e:
            print("❌ Failed to print email details.")
            import traceback
            traceback.print_exc()
