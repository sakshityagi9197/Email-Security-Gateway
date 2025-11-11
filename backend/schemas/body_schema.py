from dataclasses import dataclass, field
from typing import List, Optional

@dataclass
class EmailBody:
    uri_hash: List[str] = field(default_factory=list)
    domain_hash: List[str] = field(default_factory=list)
    content_type: Optional[str] = None
    hash: Optional[str] = None
    boundary: Optional[str] = None

    # Flattened content_header values
    content_header_content_type: List[str] = field(default_factory=list)
    content_header_content_transfer_encoding: List[str] = field(default_factory=list)
