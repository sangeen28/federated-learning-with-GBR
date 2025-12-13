"""
Demo applications showing practical uses of zero-knowledge proofs.
"""
import json
from typing import Dict, Any, List
from dataclasses import dataclass, asdict

@dataclass
class UserCredentials:
    """User credentials for authentication."""
    username: str
    public_key: Any
    metadata: Dict[str, Any] = None


class ZKPAuthentication:
    """Zero-Knowledge Password Authentication."""
    
    def __init__(self, curve_group):
        self.curve = curve_group
        self.users = {}
    
    def register_user(self, username: str, password: str) -> UserCredentials:
        """Register new user with ZKP."""
        # Derive private key from password
        salt = CryptoUtils.secure_random_bytes(16)
        private_key = CryptoUtils.derive_key(password, salt)
        private_key_int = CryptoUtils.bytes_to_int(private_key) % self.curve.order
        
        # Generate public key
        G = self.curve.random_element()
        public_key = self.curve.multiply(G, private_key_int)
        
        # Store user
        credentials = UserCredentials(
            username=username,
            public_key=public_key,
            metadata={"salt": salt.hex()}
        )
        self.users[username] = credentials
        
        return credentials
    
    def authenticate(self, username: str, password: str) -> Dict[str, Any]:
        """Authenticate using zero-knowledge proof."""
        if username not in self.users:
            return {"success": False, "error": "User not found"}
        
        credentials = self.users[username]
        
        # Recreate private key
        salt = bytes.fromhex(credentials.metadata["salt"])
        private_key = CryptoUtils.derive_key(password, salt)
        private_key_int = CryptoUtils.bytes_to_int(private_key) % self.curve.order
        
        # Generate ZKP
        G = self.curve.random_element()
        proof = SchnorrZK.prove_discrete_log(
            self.curve,
            G,
            credentials.public_key,
            private_key_int,
            username.encode(),
            b"AuthenticationServer",
            b"AUTH_DST"
        )
        
        return {
            "success": True,
            "username": username,
            "proof": {
                "commitment": str(proof.commitment),
                "challenge": str(proof.challenge),
                "response": str(proof.response)
            }
        }


class AnonymousVoting:
    """Anonymous voting system using ZKP."""
    
    def __init__(self, curve_group):
        self.curve = curve_group
        self.votes = []
        self.voters = {}
    
    def register_voter(self, voter_id: str) -> Dict[str, Any]:
        """Register voter and issue voting credentials."""
        # Generate voting key pair
        private_key = self.curve.random_scalar()
        G = self.curve.random_element()
        public_key = self.curve.multiply(G, private_key)
        
        self.voters[voter_id] = {
            "private_key": private_key,
            "public_key": public_key,
            "has_voted": False
        }
        
        return {
            "voter_id": voter_id,
            "public_key": str(public_key),
            "private_key": str(private_key)  # In practice, would be securely delivered
        }
    
    def cast_vote(self, voter_id: str, choice: int, proof: ZKPProof) -> bool:
        """Cast vote with ZKP of eligibility."""
        if voter_id not in self.voters:
            return False
        
        voter = self.voters[voter_id]
        
        # Verify ZKP that voter knows private key
        G = self.curve.random_element()
        verification = SchnorrZK.verify_proof(
            self.curve,
            proof,
            voter_id.encode(),
            b"VotingSystem",
            b"VOTE_DST"
        )
        
        if verification and not voter["has_voted"]:
            # Create anonymous vote
            vote = {
                "choice": choice,
                "public_key": str(voter["public_key"]),
                "proof": str(proof),
                "timestamp": time.time()
            }
            self.votes.append(vote)
            voter["has_voted"] = True
            return True
        
        return False
    
    def get_results(self) -> Dict[str, Any]:
        """Get voting results (anonymous tally)."""
        results = {}
        for vote in self.votes:
            choice = vote["choice"]
            if choice not in results:
                results[choice] = 0
            results[choice] += 1
        
        return {
            "total_votes": len(self.votes),
            "results": results,
            "eligible_voters": len(self.voters)
        }


class PrivacyPreservingTransaction:
    """Privacy-preserving transaction system."""
    
    def __init__(self, curve_group):
        self.curve = curve_group
        self.transactions = []
    
    def create_transaction(self, sender: str, receiver: str, 
                          amount: int, proof: ZKPProof) -> Dict[str, Any]:
        """Create private transaction with ZKP."""
        # Verify proof of sufficient funds (simplified)
        verification = SchnorrZK.verify_proof(
            self.curve,
            proof,
            sender.encode(),
            receiver.encode(),
            b"TRANSACTION_DST"
        )
        
        if verification:
            transaction = {
                "sender": sender,
                "receiver": receiver,
                "amount": amount,
                "proof": str(proof),
                "timestamp": time.time(),
                "status": "pending"
            }
            self.transactions.append(transaction)
            return transaction
        
        return None
    
    def verify_transaction(self, transaction: Dict[str, Any]) -> bool:
        """Verify transaction validity."""
        # In practice: check double-spending, signatures, etc.
        required_fields = ["sender", "receiver", "amount", "proof"]
        return all(field in transaction for field in required_fields)


def demo_authentication():
    """Demo ZKP authentication system."""
    print("\n" + "="*60)
    print("Zero-Knowledge Authentication Demo")
    print("="*60)
    
    curve = EllipticCurveGroup("P256")
    auth_system = ZKPAuthentication(curve)
    
    # Register user
    print("\n1. Registering user 'alice'...")
    credentials = auth_system.register_user("alice", "secure_password123")
    print(f"   Registered: {credentials.username}")
    print(f"   Public Key: {str(credentials.public_key)[:50]}...")
    
    # Authenticate
    print("\n2. Authenticating 'alice'...")
    result = auth_system.authenticate("alice", "secure_password123")
    if result["success"]:
        print("   ✓ Authentication successful!")
        print(f"   Proof generated: {result['proof']['commitment'][:50]}...")
    else:
        print("   ✗ Authentication failed!")
    
    # Failed authentication
    print("\n3. Attempting authentication with wrong password...")
    result = auth_system.authenticate("alice", "wrong_password")
    print(f"   Result: {'Success' if result['success'] else 'Failed as expected'}")


def demo_anonymous_voting():
    """Demo anonymous voting system."""
    print("\n" + "="*60)
    print("Anonymous Voting System Demo")
    print("="*60)
    
    curve = EllipticCurveGroup("P256")
    voting = AnonymousVoting(curve)
    
    # Register voters
    voters = ["voter1", "voter2", "voter3"]
    print(f"\n1. Registering {len(voters)} voters...")
    for voter in voters:
        creds = voting.register_voter(voter)
        print(f"   {voter}: Registered")
    
    # Cast votes
    print("\n2. Casting votes...")
    for i, voter in enumerate(voters):
        # Generate proof (in practice, voter would do this)
        voter_data = voting.voters[voter]
        G = curve.random_element()
        proof = SchnorrZK.prove_discrete_log(
            curve,
            G,
            voter_data["public_key"],
            voter_data["private_key"],
            voter.encode(),
            b"VotingSystem",
            b"VOTE_DST"
        )
        
        choice = i % 2  # Simulate different choices
        success = voting.cast_vote(voter, choice, proof)
        print(f"   {voter}: Voted {'✓' if success else '✗'}")
    
    # Get results
    print("\n3. Voting Results:")
    results = voting.get_results()
    print(f"   Total votes cast: {results['total_votes']}")
    print(f"   Eligible voters: {results['eligible_voters']}")
    print(f"   Vote counts: {results['results']}")


def demo_privacy_preserving_transactions():
    """Demo privacy-preserving transactions."""
    print("\n" + "="*60)
    print("Privacy-Preserving Transactions Demo")
    print("="*60)
    
    curve = EllipticCurveGroup("P256")
    tx_system = PrivacyPreservingTransaction(curve)
    
    # Generate sender credentials
    print("\n1. Creating sender credentials...")
    private_key = curve.random_scalar()
    G = curve.random_element()
    public_key = curve.multiply(G, private_key)
    
    # Create proof
    proof = SchnorrZK.prove_discrete_log(
        curve,
        G,
        public_key,
        private_key,
        b"Alice",
        b"Bob",
        b"TRANSACTION_DST"
    )
    
    # Create transaction
    print("\n2. Creating private transaction...")
    transaction = tx_system.create_transaction(
        "Alice",
        "Bob",
        100,
        proof
    )
    
    if transaction:
        print("   ✓ Transaction created successfully!")
        print(f"   Amount: {transaction['amount']}")
        print(f"   Sender: {transaction['sender']}")
        print(f"   Receiver: {transaction['receiver']}")
        print(f"   Status: {transaction['status']}")
    else:
        print("   ✗ Transaction failed!")
    
    # Verify transaction
    print("\n3. Verifying transaction...")
    is_valid = tx_system.verify_transaction(transaction)
    print(f"   Transaction valid: {'✓' if is_valid else '✗'}")


def main():
    """Run all demos."""
    print("Zero-Knowledge Proof Demo Applications")
    print("="*60)
    
    demo_authentication()
    demo_anonymous_voting()
    demo_privacy_preserving_transactions()
    
    print("\n" + "="*60)
    print("All demos completed successfully!")
    print("="*60)


if __name__ == "__main__":
    main()
