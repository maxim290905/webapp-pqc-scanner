#!/usr/bin/env python3
import sys
sys.path.insert(0, "/app")
from app.pqc_scanner import PQCScanner

scanner = PQCScanner()
print("Testing google.com:443...")
result = scanner.scan_target("google.com", 443, hybrid_only=False, timeout=10.0)
print(f"PQC Supported: {result.get('pqc_supported')}")
print(f"PQC Algos: {result.get('pqc_algos')}")
print(f"Hybrid Algos: {result.get('hybrid_algos')}")
print(f"Error: {result.get('error')}")

