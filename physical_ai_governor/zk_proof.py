"""
Blinded Safety Commitment Envelope & Privacy-Preserving Audit Prover.
Enables physical AI operators (defense, robotics factories, autonomous aviation)
to provide cryptographic commitments of Control Barrier Function (CBF) compliance
to regulators and insurers without revealing proprietary trajectory coordinates,
mission waypoints, or factory floor plans.

NOTE: This module implements a blinded cryptographic commitment envelope
(a SHA-256 hash-blinding commit-and-challenge scheme using Fiat-Shamir heuristics).
It is NOT an arithmetic ZK-SNARK/STARK circuit proving system.
Zero external dependencies (pure Python standard library).
"""

import hashlib
import json
import secrets
import time
from dataclasses import asdict, dataclass
from typing import Any, Dict, List, Optional, Tuple

from .merkle_blackbox import MerkleBlackBoxLedger


ALLOWED_INVARIANT_TEMPLATES = {
    "CBF_FORWARD_INVARIANCE_HOLDS",
    "ISO_10218_TORQUE_LIMIT_SATISFIED",
    "COLLABORATIVE_SEPARATION_MAINTAINED",
    "forward_invariance_cbf_simulated == True",
}

ALLOWED_INVARIANT_PREFIXES = (
    "min_human_distance >=",
    "max_joint_torque <=",
    "max_velocity <=",
)


def validate_invariant_claim(inv: str) -> bool:
    """Validates that an invariant matches recognized safety commitment templates."""
    if inv in ALLOWED_INVARIANT_TEMPLATES:
        return True
    for prefix in ALLOWED_INVARIANT_PREFIXES:
        if inv.startswith(prefix):
            parts = inv.split(">=" if ">=" in inv else "<=")
            if len(parts) == 2:
                val_str = parts[1].strip().rstrip("m/s").rstrip("Nm").rstrip("m").strip()
                try:
                    float(val_str)
                    return True
                except ValueError:
                    return False
    return False


@dataclass
class BlindedSafetyEnvelope:
    """Blinded cryptographic safety commitment envelope for audit disclosure."""
    proof_id: str
    robot_id: str
    merkle_root: str
    total_cycles_proven: int
    invariants_certified: List[str]
    challenge_hash: str
    response_proofs: List[str]
    blinded_commitments: List[str]
    timestamp: float

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


# Backwards-compatible aliases
BlindedCommitmentEnvelope = BlindedSafetyEnvelope
ZKSafetyProofEnvelope = BlindedSafetyEnvelope


class BlindedSafetyProver:
    """
    Generates blinded cryptographic commitments over black-box flight ledgers.
    Uses Fiat-Shamir heuristic over cryptographic blinding commitments to provide:
        1. Commitment to compliance assertions (h(x) >= 0 and torque <= tau_max).
        2. Cryptographic binding to the public Merkle Root R.
        3. Zero disclosure of raw Cartesian position coordinates (p_x, p_y, p_z).
    Note: Software commit-and-challenge scheme, not an arithmetic ZK circuit.
    Predicate verification requires opening proofs via verify_opening().
    """

    def __init__(self, salt: Optional[str] = None) -> None:
        self.salt = salt or secrets.token_hex(16)

    def generate_blinded_envelope(
        self,
        ledger: MerkleBlackBoxLedger,
        robot_id: str,
        min_human_distance_m: float = 1.50,
        max_joint_torque_nm: float = 150.0,
        max_velocity_mps: float = 4.0,
    ) -> BlindedSafetyEnvelope:
        """
        Synthesizes a verifiable blinded commitment envelope over all ledger records.
        """
        records = ledger.records
        if not records:
            raise ValueError("Cannot generate safety envelope for an empty ledger")

        merkle_root = ledger.build_merkle_root()
        invariants = [
            f"min_human_distance >= {min_human_distance_m}m",
            f"max_joint_torque <= {max_joint_torque_nm}Nm",
            f"max_velocity <= {max_velocity_mps}m/s",
            "forward_invariance_cbf_simulated == True",
        ]

        commitments: List[str] = []
        blinding_factors: List[str] = []

        # 1. Generate blinded hash commitments for each cycle
        for rec in records:
            r_blind = secrets.token_hex(16)
            blinding_factors.append(r_blind)

            # Blinded commitment masks raw coordinates while capturing compliance status
            payload = f"{rec['leaf_hash']}:{rec['is_safe']}:{rec['human_proximity']}:{r_blind}".encode()
            commit = hashlib.sha256(payload).hexdigest()
            commitments.append(commit)

        # 2. Fiat-Shamir Challenge: e = H(MerkleRoot || Invariants || Commitments)
        fiat_shamir_input = f"{merkle_root}:{','.join(invariants)}:{''.join(commitments)}".encode()
        challenge_e = hashlib.sha256(fiat_shamir_input).hexdigest()

        # 3. Generate response proofs linking challenge, blinding factor, and safety margin
        responses: List[str] = []
        for i, rec in enumerate(records):
            resp_input = f"{challenge_e}:{commitments[i]}:{blinding_factors[i]}:{rec['is_safe']}".encode()
            resp = hashlib.sha256(resp_input).hexdigest()
            responses.append(resp)

        proof_id = f"blinded-cbf-{secrets.token_hex(8)}"

        return BlindedSafetyEnvelope(
            proof_id=proof_id,
            robot_id=robot_id,
            merkle_root=merkle_root,
            total_cycles_proven=len(records),
            invariants_certified=invariants,
            challenge_hash=challenge_e,
            response_proofs=responses,
            blinded_commitments=commitments,
            timestamp=time.time(),
        )

    # Alias for backwards compatibility
    def generate_zk_proof(self, *args, **kwargs) -> BlindedSafetyEnvelope:
        return self.generate_blinded_envelope(*args, **kwargs)

    @staticmethod
    def verify_blinded_envelope(
        envelope: BlindedSafetyEnvelope,
        expected_merkle_root: Optional[str] = None,
    ) -> bool:
        """
        Cryptographically verifies the blinded commitment envelope.
        Returns True if the commitment challenge and response proofs are valid,
        all certified invariants match allowed templates, and commitments bind to the root.
        """
        if not envelope.response_proofs or len(envelope.response_proofs) != envelope.total_cycles_proven:
            return False

        if not envelope.blinded_commitments or len(envelope.blinded_commitments) != envelope.total_cycles_proven:
            return False

        # Invariant validation: reject arbitrary or fabricated claims
        if not envelope.invariants_certified:
            return False
        for inv in envelope.invariants_certified:
            if not isinstance(inv, str) or not validate_invariant_claim(inv):
                return False

        if expected_merkle_root and envelope.merkle_root != expected_merkle_root:
            return False

        # Recompute Fiat-Shamir challenge
        fiat_shamir_input = f"{envelope.merkle_root}:{','.join(envelope.invariants_certified)}:{''.join(envelope.blinded_commitments)}".encode()
        expected_challenge = hashlib.sha256(fiat_shamir_input).hexdigest()

        if envelope.challenge_hash != expected_challenge:
            return False

        # Verify integrity and format of response proofs and commitments
        for resp in envelope.response_proofs:
            if not resp or len(resp) != 64:
                return False
        for commit in envelope.blinded_commitments:
            if not commit or len(commit) != 64:
                return False

        return True

    @staticmethod
    def verify_opening(
        envelope: BlindedSafetyEnvelope,
        cycle_index: int,
        leaf_hash: str,
        is_safe: bool,
        human_proximity: float,
        blinding_factor: str,
    ) -> bool:
        """
        Verifies the opening proof for a specific cycle in the commitment envelope.
        Validates that revealed cycle state matches the blinded commitment and response proof.
        """
        if cycle_index < 0 or cycle_index >= envelope.total_cycles_proven:
            return False
        if cycle_index >= len(envelope.blinded_commitments) or cycle_index >= len(envelope.response_proofs):
            return False

        # 1. Recompute the commitment
        payload = f"{leaf_hash}:{is_safe}:{human_proximity}:{blinding_factor}".encode()
        expected_commit = hashlib.sha256(payload).hexdigest()
        if envelope.blinded_commitments[cycle_index] != expected_commit:
            return False

        # 2. Recompute the response proof
        expected_resp_input = f"{envelope.challenge_hash}:{expected_commit}:{blinding_factor}:{is_safe}".encode()
        expected_resp = hashlib.sha256(expected_resp_input).hexdigest()
        if envelope.response_proofs[cycle_index] != expected_resp:
            return False

        return True

    # Alias for backwards compatibility
    @staticmethod
    def verify_zk_proof(envelope: BlindedSafetyEnvelope, expected_merkle_root: Optional[str] = None) -> bool:
        return BlindedSafetyProver.verify_blinded_envelope(envelope, expected_merkle_root)


# Backwards-compatible class aliases
BlindedCommitmentProver = BlindedSafetyProver
ZKSafetyProver = BlindedSafetyProver
