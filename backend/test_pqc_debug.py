#!/usr/bin/env python3
import sys
sys.path.insert(0, "/app")
from app.pqc_scanner import PQCScanner
import json

scanner = PQCScanner()
print("Testing google.com:443 with debug output...")
print(f"Total groups in config: {len(scanner.groups)}")

# Test a few specific groups
test_groups = [
    ("MLKEM768", 513),
    ("MLKEM1024", 514),
    ("X25519MLKEM768", 4588),
    ("SECP256R1MLKEM768", 4587),
]

for group_name, group_id in test_groups:
    print(f"\n=== Testing {group_name} (group_id: {group_id}) ===")
    supported, selected, supported_groups = scanner.scan_group("google.com", 443, group_id, group_name, timeout=10.0)
    print(f"Supported: {supported}")
    if selected is not None:
        print(f"Selected group: {selected} (0x{selected:04x})")
    else:
        print(f"Selected group: None")
    print(f"Supported groups list: {supported_groups}")
    if supported_groups:
        print("  Checking if any are PQC:")
        for sg in supported_groups:
            for name, info in scanner.groups.items():
                if info.get("group_id") == sg:
                    if info.get("pqc", False):
                        print(f"    - {name} (0x{sg:04x}) [PQC]")
                    break

print("\n=== Full scan ===")
result = scanner.scan_target("google.com", 443, hybrid_only=False, timeout=10.0)
print(f"PQC Supported: {result.get('pqc_supported')}")
print(f"PQC Algos: {result.get('pqc_algos')}")
print(f"Hybrid Algos: {result.get('hybrid_algos')}")

