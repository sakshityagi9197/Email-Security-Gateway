from dataclasses import dataclass
from typing import Optional, List

@dataclass
class AttachmentInfo:
    filename: Optional[str] = None
    size: Optional[int] = None
    extension: Optional[str] = None

    # Hashes
    hash_md5: Optional[str] = None 
    hash_sha1: Optional[str] = None
    hash_sha256: Optional[str] = None
    hash_sha512: Optional[str] = None

    # Content headers
    content_type: Optional[List[str]] = None
    content_disposition: Optional[List[str]] = None
    content_transfer_encoding: Optional[List[str]] = None

    # Additional fields for URLs and raw content
    extracted_urls: Optional[List[str]] = None
    raw_content: Optional[bytes] = None