"""Tiny helper to test ClamAV detection.

This file inserts the repository root into sys.path so it can be
run directly from the workspace without requiring PYTHONPATH.
"""
import sys
from pathlib import Path

# Ensure project root is on sys.path (two levels up from tools/)
repo_root = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(repo_root))

from backend.threat_detection import clamav_scanner

exe, attempted = clamav_scanner._find_clamscan(None)
print('discovered_exe:', exe)
print('attempted candidates:', attempted)

# Perform a quick scan of this script (will return an error dict if clamscan missing)
res = clamav_scanner.scan_with_clamav(__file__)
print('scan result for this file:', res)
