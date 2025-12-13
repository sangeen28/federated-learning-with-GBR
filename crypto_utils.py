"""
Cryptographic utilities and helper functions.
"""
import os
import base64
import hashlib
import hmac
from typing import Union, Optional
from cryptography.hazmat.primitives import constant_time

class CryptoUtils:
    """Collection of cryptographic utility functions."""
    
    @staticmethod
    def secure_random_bytes(length: int) -> bytes:
        """Generate cryptographically secure random bytes."""
        return os.urandom(length)
    
    @staticmethod
    def derive_key(password: str, salt: bytes, iterations: int = 100000) -> bytes:
        """Derive key from password using PBKDF2."""
        return hashlib.pbkdf2_hmac(
            'sha256',
            password.encode('utf-8'),
            salt,
            iterations,
            dklen=32
        )
    
    @staticmethod
    def hmac_sha256(key: bytes, data: bytes) -> bytes:
        """Compute HMAC-SHA256."""
        return hmac.new(key, data, hashlib.sha256).digest()
    
    @staticmethod
    def constant_time_compare(a: bytes, b: bytes) -> bool:
        """Constant-time comparison to prevent timing attacks."""
        return constant_time.bytes_eq(a, b)
    
    @staticmethod
    def bytes_to_int(b: bytes) -> int:
        """Convert bytes to integer."""
        return int.from_bytes(b, 'big', signed=False)
    
    @staticmethod
    def int_to_bytes(i: int, length: Optional[int] = None) -> bytes:
        """Convert integer to bytes."""
        if length is None:
            length = (i.bit_length() + 7) // 8
        return i.to_bytes(length, 'big', signed=False)
    
    @staticmethod
    def xor_bytes(a: bytes, b: bytes) -> bytes:
        """XOR two byte strings."""
        return bytes(x ^ y for x, y in zip(a, b))


class DomainSeparation:
    """Domain separation for cryptographic operations."""
    
    def __init__(self):
        self.contexts = {}
    
    def add_context(self, name: str, context: bytes):
        """Add a domain separation context."""
        self.contexts[name] = context
    
    def get_context(self, *names: str) -> bytes:
        """Combine multiple contexts for domain separation."""
        combined = b""
        for name in names:
            if name in self.contexts:
                combined += self.contexts[name]
        return combined


class ZKPBenchmark:
    """Benchmarking utility for ZKP operations."""
    
    def __init__(self):
        self.times = {}
    
    def start(self, operation: str):
        """Start timing an operation."""
        self.times[operation] = {"start": time.time()}
    
    def end(self, operation: str):
        """End timing and calculate duration."""
        if operation in self.times and "start" in self.times[operation]:
            duration = time.time() - self.times[operation]["start"]
            self.times[operation]["duration"] = duration
            return duration
        return None
    
    def print_report(self):
        """Print benchmarking report."""
        print("\n" + "="*50)
        print("ZKP Performance Benchmark Report")
        print("="*50)
        for op, data in self.times.items():
            if "duration" in data:
                print(f"{op:<30}: {data['duration']:.6f} seconds")
        print("="*50)
