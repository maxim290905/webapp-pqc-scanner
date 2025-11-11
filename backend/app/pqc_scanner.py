"""
Post-Quantum Cryptography Scanner
Python port of pqcscan Rust scanner
"""
import json
import socket
import struct
import random
import time
from typing import Dict, List, Optional, Tuple
from pathlib import Path


class TLSClientHello:
    """Build TLS ClientHello messages"""
    
    def __init__(self, hostname: str):
        self.hostname = hostname
        self.random = bytes([random.getrandbits(8) for _ in range(32)])
        self.session_id = bytes([random.getrandbits(8) for _ in range(32)])
        self.cipher_suites = []
        self.extensions = []
        
    def add_cipher_suite(self, suite_id: int):
        self.cipher_suites.append(suite_id)
    
    def add_extension(self, ext_type: int, ext_data: bytes):
        self.extensions.append((ext_type, ext_data))
    
    def build(self) -> bytes:
        """Build complete TLS ClientHello record"""
        # Handshake message
        handshake = bytearray()
        
        # ClientHello
        handshake.append(0x01)  # Handshake type: ClientHello
        
        # Handshake length (will be filled later)
        handshake_len_pos = len(handshake)
        handshake.extend(b'\x00\x00\x00')
        
        # Legacy version
        handshake.extend(struct.pack('>H', 0x0303))  # TLS 1.2
        
        # Random
        handshake.extend(self.random)
        
        # Session ID
        handshake.append(len(self.session_id))
        handshake.extend(self.session_id)
        
        # Cipher suites
        cipher_suites_len = len(self.cipher_suites) * 2
        handshake.extend(struct.pack('>H', cipher_suites_len))
        for suite in self.cipher_suites:
            handshake.extend(struct.pack('>H', suite))
        
        # Compression methods
        handshake.append(1)  # Length
        handshake.append(0)  # NULL compression
        
        # Extensions
        extensions_data = bytearray()
        for ext_type, ext_data in self.extensions:
            extensions_data.extend(struct.pack('>H', ext_type))
            extensions_data.extend(struct.pack('>H', len(ext_data)))
            extensions_data.extend(ext_data)
        
        handshake.extend(struct.pack('>H', len(extensions_data)))
        handshake.extend(extensions_data)
        
        # Fill handshake length
        handshake_len = len(handshake) - 4
        handshake[handshake_len_pos:handshake_len_pos+3] = struct.pack('>I', handshake_len)[1:]
        
        # TLS Record Layer
        record = bytearray()
        record.append(0x16)  # Content type: Handshake
        record.extend(struct.pack('>H', 0x0301))  # Legacy version
        record.extend(struct.pack('>H', len(handshake)))
        record.extend(handshake)
        
        return bytes(record)
    
    def add_server_name_extension(self):
        """Add Server Name Indication extension"""
        hostname_bytes = self.hostname.encode('utf-8')
        ext_data = bytearray()
        ext_data.extend(struct.pack('>H', len(hostname_bytes) + 3))
        ext_data.append(0)  # Name type: host_name
        ext_data.extend(struct.pack('>H', len(hostname_bytes)))
        ext_data.extend(hostname_bytes)
        self.add_extension(0, bytes(ext_data))
    
    def add_supported_versions_extension(self):
        """Add Supported Versions extension"""
        ext_data = bytearray()
        ext_data.append(2)  # Length of versions list
        ext_data.extend(struct.pack('>H', 0x0304))  # TLS 1.3
        self.add_extension(43, bytes(ext_data))
    
    def add_supported_groups_extension(self, groups: List[int]):
        """Add Supported Groups extension"""
        ext_data = bytearray()
        groups_len = len(groups) * 2
        ext_data.extend(struct.pack('>H', groups_len))
        for group in groups:
            ext_data.extend(struct.pack('>H', group))
        self.add_extension(10, bytes(ext_data))
    
    def add_signature_algorithms_extension(self, schemes: List[int]):
        """Add Signature Algorithms extension"""
        ext_data = bytearray()
        schemes_len = len(schemes) * 2
        ext_data.extend(struct.pack('>H', schemes_len))
        for scheme in schemes:
            ext_data.extend(struct.pack('>H', scheme))
        self.add_extension(13, bytes(ext_data))
    
    def add_key_share_extension(self):
        """Add Key Share extension (empty for now)"""
        ext_data = bytearray()
        ext_data.extend(struct.pack('>H', 0))  # Empty key share
        self.add_extension(51, bytes(ext_data))


class PQCScanner:
    """Post-Quantum Cryptography Scanner"""
    
    def __init__(self):
        self.groups = self._load_groups()
        self.cipher_suites = self._load_cipher_suites()
        self.sig_schemes = self._load_sig_schemes()
    
    def _load_groups(self) -> Dict:
        """Load TLS groups from JSON"""
        json_path = Path(__file__).parent / "tls_groups.json"
        with open(json_path, 'r') as f:
            return json.load(f)
    
    def _load_cipher_suites(self) -> List[int]:
        """Load standard TLS 1.3 cipher suites"""
        # Common TLS 1.3 cipher suites
        return [
            0x1301,  # TLS_AES_128_GCM_SHA256
            0x1302,  # TLS_AES_256_GCM_SHA384
            0x1303,  # TLS_CHACHA20_POLY1305_SHA256
        ]
    
    def _load_sig_schemes(self) -> List[int]:
        """Load standard signature schemes"""
        return [
            0x0401,  # rsa_pkcs1_sha256
            0x0501,  # rsa_pkcs1_sha512
            0x0804,  # rsa_pss_sha256
            0x0805,  # rsa_pss_sha384
            0x0806,  # rsa_pss_sha512
            0x0403,  # ecdsa_secp256r1_sha256
            0x0503,  # ecdsa_secp384r1_sha384
            0x0603,  # ecdsa_secp521r1_sha512
            0x0807,  # ed25519
            0x0808,  # ed448
        ]
    
    def _connect(self, host: str, port: int, timeout: float = 5.0) -> Optional[socket.socket]:
        """Create TCP connection to host:port"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            sock.connect((host, port))
            return sock
        except Exception as e:
            return None
    
    def _send_client_hello(self, sock: socket.socket, client_hello: bytes) -> Optional[bytes]:
        """Send ClientHello and receive response"""
        try:
            sock.sendall(client_hello)
            response = sock.recv(4096)
            return response
        except Exception as e:
            return None
    
    def _parse_server_hello(self, response: bytes, expected_group: int) -> Tuple[bool, Optional[int], List[int]]:
        """Parse ServerHello response to check if handshake succeeded and which group was selected"""
        if len(response) < 5:
            return False, None, []
        
        # Check content type
        # 0x16 = Handshake (ServerHello)
        # 0x15 = Alert (server doesn't support the group)
        if response[0] == 0x15:
            # Server sent Alert - doesn't support the requested group
            return False, None, []
        
        # Check content type (0x16 = Handshake)
        if response[0] != 0x16:
            return False, None, []
        
        # Check TLS version
        if response[1:3] != b'\x03\x03':
            return False, None, []
        
        record_length = struct.unpack('>H', response[3:5])[0]
        
        # Check handshake type (0x02 = ServerHello)
        if len(response) < 11 or response[5] != 0x02:
            return False, None, []
        
        # Parse handshake length (3 bytes)
        handshake_len = struct.unpack('>I', b'\x00' + response[6:9])[0]
        
        # Skip to ServerHello body (after version)
        pos = 11  # After: content_type(1) + version(2) + length(2) + handshake_type(1) + handshake_len(3) + version(2)
        
        if len(response) < pos + 32:
            return False, None, []
        
        # Skip random (32 bytes)
        pos += 32
        
        # Skip session ID
        if pos >= len(response):
            return False, None, []
        session_id_len = response[pos]
        pos += 1 + session_id_len
        
        # Skip cipher suite (2 bytes)
        if pos + 2 > len(response):
            return False, None, []
        pos += 2
        
        # Skip compression method (1 byte)
        if pos >= len(response):
            return False, None, []
        pos += 1
        
        # Parse extensions
        if pos + 2 > len(response):
            return False, None, []
        extensions_len = struct.unpack('>H', response[pos:pos+2])[0]
        pos += 2
        
        extensions_end = pos + extensions_len
        selected_group = None
        supported_groups_list = []
        
        # Parse extensions to find key_share (51) and supported_groups (10)
        while pos < extensions_end and pos + 4 <= len(response):
            ext_type = struct.unpack('>H', response[pos:pos+2])[0]
            ext_len = struct.unpack('>H', response[pos+2:pos+4])[0]
            pos += 4
            
            if pos + ext_len > len(response):
                break
            
            # Supported Groups extension (10) - contains list of groups server supports
            if ext_type == 10:
                if ext_len >= 2:
                    groups_len = struct.unpack('>H', response[pos:pos+2])[0]
                    groups_count = groups_len // 2
                    for i in range(groups_count):
                        if pos + 2 + (i * 2) + 2 <= len(response):
                            group = struct.unpack('>H', response[pos + 2 + (i * 2):pos + 2 + (i * 2) + 2])[0]
                            supported_groups_list.append(group)
            
            # Key Share extension (51) - contains the selected group
            if ext_type == 51:
                if ext_len >= 2:
                    key_share_len = struct.unpack('>H', response[pos:pos+2])[0]
                    if key_share_len >= 2 and pos + 4 <= len(response):
                        selected_group = struct.unpack('>H', response[pos+2:pos+4])[0]
            
            pos += ext_len
        
        # Rust scanner logic: if we got ServerHello (not Alert), the group is supported!
        # This is because in TLS 1.3, if server doesn't support the group we requested,
        # it would send HelloRetryRequest or Alert, not ServerHello.
        # If server sent ServerHello, it means it supports our group (even if it selected another).
        # This matches the Rust pqcscan behavior.
        return True, selected_group, supported_groups_list
    
    def scan_group(self, host: str, port: int, group_id: int, group_name: str, timeout: float = 5.0) -> Tuple[bool, Optional[int], List[int]]:
        """Test if server supports a specific group"""
        sock = self._connect(host, port, timeout)
        if not sock:
            return False, None, []
        
        try:
            # Build ClientHello with this group in supported_groups AND key_share
            # For TLS 1.3, we need to send key_share with the group we want to test
            client_hello = TLSClientHello(host)
            client_hello.add_cipher_suite(0x1301)  # TLS_AES_128_GCM_SHA256
            client_hello.add_server_name_extension()
            client_hello.add_supported_versions_extension()
            client_hello.add_supported_groups_extension([group_id])
            client_hello.add_signature_algorithms_extension(self.sig_schemes)
            
            # Add key_share with empty key (server will respond with its key_share)
            # For testing, we can send empty key_share and server will respond with its choice
            client_hello.add_key_share_extension()
            
            hello_bytes = client_hello.build()
            response = self._send_client_hello(sock, hello_bytes)
            
            if response:
                supported, selected, supported_groups = self._parse_server_hello(response, group_id)
                return supported, selected, supported_groups
            
            return False, None, []
        except Exception as e:
            # Connection or parsing error
            return False, None, []
        finally:
            sock.close()
    
    def scan_target(self, host: str, port: int = 443, hybrid_only: bool = False, timeout: float = 5.0, progress_callback=None) -> Dict:
        """Scan target for PQC support"""
        results = {
            "host": host,
            "port": port,
            "pqc_supported": False,
            "pqc_algos": [],
            "hybrid_algos": [],
            "nonpqc_algos": [],
            "error": None
        }
        
        # Filter groups to test
        groups_to_test = []
        for name, group_info in self.groups.items():
            if hybrid_only and not group_info.get("hybrid", False):
                continue
            if group_info.get("pqc", False):
                groups_to_test.append((name, group_info))
        
        if not groups_to_test:
            results["error"] = "No PQC groups to test"
            return results
        
        # Test each group (limit to first 20 to avoid timeout)
        # Prioritize common PQC groups first
        priority_groups = ["MLKEM768", "MLKEM1024", "X25519MLKEM768", "SECP256R1MLKEM768", 
                          "MLKEM512", "MLKEMED25519", "ED25519MLKEM768"]
        
        # Sort groups: priority first, then others
        def sort_key(item):
            name, _ = item
            if name in priority_groups:
                return (0, priority_groups.index(name))
            return (1, name)
        
        groups_to_test = sorted(groups_to_test, key=sort_key)[:20]
        total_groups = len(groups_to_test)
        
        for idx, (group_name, group_info) in enumerate(groups_to_test):
            if progress_callback:
                progress_callback(f"Тестирование PQC группы {idx+1}/{total_groups}: {group_name}")
            group_id = group_info["group_id"]
            is_pqc = group_info.get("pqc", False)
            is_hybrid = group_info.get("hybrid", False)
            
            try:
                supported, selected_group, supported_groups = self.scan_group(host, port, group_id, group_name, timeout)
                
                # Always check if selected_group is PQC (even if supported=False)
                # This helps us discover PQC support even when testing non-PQC groups
                if selected_group is not None:
                    for other_name, other_info in self.groups.items():
                        if other_info.get("group_id") == selected_group:
                            if other_info.get("pqc", False):
                                # Server selected a PQC group - definitely supports PQC
                                results["pqc_supported"] = True
                                if other_info.get("hybrid", False):
                                    if other_name not in results["hybrid_algos"]:
                                        results["hybrid_algos"].append(other_name)
                                elif other_name not in results["pqc_algos"]:
                                    results["pqc_algos"].append(other_name)
                            break
                
                if supported:
                    # Rust scanner logic: if we got ServerHello, the group is supported!
                    # Add the group we tested to results
                    if is_hybrid:
                        if group_name not in results["hybrid_algos"]:
                            results["hybrid_algos"].append(group_name)
                        results["pqc_supported"] = True
                    elif is_pqc:
                        if group_name not in results["pqc_algos"]:
                            results["pqc_algos"].append(group_name)
                        results["pqc_supported"] = True
                    else:
                        results["nonpqc_algos"].append(group_name)
                    
                    # Also check if server selected a PQC group (even if different from ours)
                    if selected_group is not None:
                        for other_name, other_info in self.groups.items():
                            if other_info.get("group_id") == selected_group:
                                if other_info.get("pqc", False):
                                    results["pqc_supported"] = True
                                    if other_info.get("hybrid", False):
                                        if other_name not in results["hybrid_algos"]:
                                            results["hybrid_algos"].append(other_name)
                                    elif other_name not in results["pqc_algos"]:
                                        results["pqc_algos"].append(other_name)
                                break
                    
                    # Also check supported_groups list for PQC groups
                    if supported_groups:
                        for supported_group_id in supported_groups:
                            for other_name, other_info in self.groups.items():
                                if other_info.get("group_id") == supported_group_id:
                                    if other_info.get("pqc", False):
                                        results["pqc_supported"] = True
                                        if other_info.get("hybrid", False):
                                            if other_name not in results["hybrid_algos"]:
                                                results["hybrid_algos"].append(other_name)
                                        elif other_name not in results["pqc_algos"]:
                                            results["pqc_algos"].append(other_name)
                                    break
            except Exception as e:
                # Continue testing other groups
                pass
        
        return results

