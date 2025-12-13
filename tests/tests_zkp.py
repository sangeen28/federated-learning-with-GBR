"""
Unit tests for Zero-Knowledge Proof implementations.
"""
import unittest
import time
from typing import Dict, Any

# Import your modules
from elliptic_curve_operations import EllipticCurveGroup, CurveOperations
from zkp_protocols import SchnorrZK, ChaumPedersenZK, ZKPProof
from signature_schemes import SchnorrSignature, Signature
from crypto_utils import CryptoUtils, ZKPBenchmark


class TestEllipticCurveOperations(unittest.TestCase):
    """Test elliptic curve operations."""
    
    def setUp(self):
        self.curve = EllipticCurveGroup("P256")
    
    def test_keypair_generation(self):
        """Test key pair generation."""
        private_key, public_key = CurveOperations.generate_keypair(self.curve)
        self.assertIsNotNone(private_key)
        self.assertIsNotNone(public_key)
    
    def test_pedersen_commitment(self):
        """Test Pedersen commitment."""
        value = 42
        blinding = self.curve.random_scalar()
        commitment = CurveOperations.pedersen_commitment(self.curve, value, blinding)
        self.assertIsNotNone(commitment)


class TestSchnorrZK(unittest.TestCase):
    """Test Schnorr Zero-Knowledge Proof."""
    
    def setUp(self):
        self.curve = EllipticCurveGroup("P256")
        self.G = self.curve.random_element()
        self.x = self.curve.random_scalar()
        self.X = self.curve.multiply(self.G, self.x)
    
    def test_prove_verify(self):
        """Test complete prove-verify cycle."""
        proof = SchnorrZK.prove_discrete_log(
            self.curve,
            self.G,
            self.X,
            self.x,
            b"Prover",
            b"Verifier",
            b"TEST_DST"
        )
        
        result = SchnorrZK.verify_proof(
            self.curve,
            proof,
            b"Prover",
            b"Verifier",
            b"TEST_DST"
        )
        
        self.assertTrue(result)
    
    def test_wrong_secret_fails(self):
        """Test that wrong secret fails verification."""
        wrong_x = self.curve.random_scalar()
        
        proof = SchnorrZK.prove_discrete_log(
            self.curve,
            self.G,
            self.X,
            wrong_x,  # Wrong secret!
            b"Prover",
            b"Verifier",
            b"TEST_DST"
        )
        
        result = SchnorrZK.verify_proof(
            self.curve,
            proof,
            b"Prover",
            b"Verifier",
            b"TEST_DST"
        )
        
        self.assertFalse(result)


class TestSchnorrSignature(unittest.TestCase):
    """Test Schnorr signature scheme."""
    
    def setUp(self):
        self.curve = EllipticCurveGroup("P256")
        self.signer = SchnorrSignature(self.curve)
        self.private_key = self.curve.random_scalar()
    
    def test_sign_verify(self):
        """Test signature creation and verification."""
        message = b"Test message for signing"
        
        signature = self.signer.sign(self.private_key, message)
        result = self.signer.verify(signature)
        
        self.assertTrue(result)
    
    def test_tampered_message(self):
        """Test that tampered message fails verification."""
        message = b"Original message"
        signature = self.signer.sign(self.private_key, message)
        
        # Tamper with message
        signature.message = b"Tampered message"
        result = self.signer.verify(signature)
        
        self.assertFalse(result)


class TestCryptoUtils(unittest.TestCase):
    """Test cryptographic utilities."""
    
    def test_secure_random_bytes(self):
        """Test secure random byte generation."""
        bytes1 = CryptoUtils.secure_random_bytes(32)
        bytes2 = CryptoUtils.secure_random_bytes(32)
        
        self.assertEqual(len(bytes1), 32)
        self.assertEqual(len(bytes2), 32)
        self.assertNotEqual(bytes1, bytes2)
    
    def test_constant_time_compare(self):
        """Test constant-time comparison."""
        a = b"test string"
        b = b"test string"
        c = b"different string"
        
        self.assertTrue(CryptoUtils.constant_time_compare(a, b))
        self.assertFalse(CryptoUtils.constant_time_compare(a, c))
    
    def test_hmac_sha256(self):
        """Test HMAC-SHA256."""
        key = b"test key"
        data = b"test data"
        hmac_result = CryptoUtils.hmac_sha256(key, data)
        
        self.assertEqual(len(hmac_result), 32)  # SHA256 produces 32 bytes


class TestZKPBenchmark(unittest.TestCase):
    """Test ZKP benchmarking."""
    
    def test_benchmark(self):
        """Test benchmarking functionality."""
        benchmark = ZKPBenchmark()
        
        benchmark.start("test_operation")
        time.sleep(0.1)  # Simulate work
        duration = benchmark.end("test_operation")
        
        self.assertIsNotNone(duration)
        self.assertGreater(duration, 0.09)


def run_performance_test():
    """Run performance tests and generate report."""
    print("Running Performance Tests...")
    print("="*50)
    
    benchmark = ZKPBenchmark()
    curve = EllipticCurveGroup("P256")
    
    # Generate keypair
    benchmark.start("Key Generation")
    private_key, public_key = CurveOperations.generate_keypair(curve)
    benchmark.end("Key Generation")
    
    # Schnorr proof
    G = curve.random_element()
    X = curve.multiply(G, private_key)
    
    benchmark.start("Schnorr Proof Generation")
    proof = SchnorrZK.prove_discrete_log(
        curve, G, X, private_key,
        b"PerfTest", b"Verifier", b"PERF_DST"
    )
    benchmark.end("Schnorr Proof Generation")
    
    benchmark.start("Schnorr Proof Verification")
    result = SchnorrZK.verify_proof(
        curve, proof,
        b"PerfTest", b"Verifier", b"PERF_DST"
    )
    benchmark.end("Schnorr Proof Verification")
    
    print(f"Verification result: {result}")
    benchmark.print_report()


if __name__ == "__main__":
    # Run unit tests
    print("Running Unit Tests...")
    unittest.main(exit=False)
    
    # Run performance tests
    run_performance_test()
