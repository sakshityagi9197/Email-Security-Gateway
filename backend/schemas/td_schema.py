from dataclasses import dataclass
from typing import Optional, List, Dict

@dataclass
class ThreatDetectionResult:
    # Overall threat scores
    threat_score: Optional[float] = None
    confidence_level: Optional[float] = None
    
    # Sandbox analysis results
    sandbox_result: Optional[Dict] = None
    sandbox_verdict: Optional[str] = None
    sandbox_analysis_time: Optional[float] = None
    
    # URL related threats
    malicious_urls: Optional[List[str]] = None
    suspicious_urls: Optional[List[str]] = None
    url_reputation_scores: Optional[Dict[str, float]] = None
    
    # File analysis
    file_reputation: Optional[str] = None
    detected_malware: Optional[List[str]] = None
    file_classification: Optional[str] = None
    
    # Behavioral indicators
    iocs: Optional[List[Dict]] = None  # Indicators of Compromise
    detected_behaviors: Optional[List[str]] = None
    
    # Network analysis
    detected_c2_servers: Optional[List[str]] = None
    suspicious_connections: Optional[List[Dict]] = None
    
    # Additional metadata
    analysis_timestamp: Optional[str] = None
    scan_engines: Optional[List[str]] = None
    scan_engine_results: Optional[Dict] = None
    
    # Risk assessment
    risk_level: Optional[str] = None
    
    def __post_init__(self):
        # Initialize empty collections if None
        if self.malicious_urls is None:
            self.malicious_urls = []
        if self.suspicious_urls is None:
            self.suspicious_urls = []
        if self.detected_malware is None:
            self.detected_malware = []
        if self.iocs is None:
            self.iocs = []