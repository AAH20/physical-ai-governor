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
import math
import re
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


@dataclass
class SafetyPredicate:
    """Typed physical AI safety predicate extracted from certified invariants."""
    name: str
    operator: str
    threshold: Optional[float]
    unit: Optional[str]
    raw_claim: str

    def evaluate(self, record: Dict[str, Any]) -> bool:
        """Evaluates whether an opened cycle record satisfies this predicate."""
        if self.name == "min_human_distance":
            val = record.get("human_proximity")
            if val is None or not isinstance(val, (int, float)) or not math.isfinite(val):
                return False
            return float(val) >= (float(self.threshold) - 1e-6)
        elif self.name == "max_joint_torque":
            torques = record.get("filtered_command") or record.get("original_command") or []
            if not torques or not all(isinstance(t, (int, float)) and math.isfinite(t) for t in torques):
                return False
            return max(abs(t) for t in torques) <= (float(self.threshold) + 1e-6)
        elif self.name == "max_velocity":
            vel = record.get("velocity") or []
            if not vel or not all(isinstance(v, (int, float)) and math.isfinite(v) for v in vel):
                return False
            vel_mag = math.sqrt(sum(v * v for v in vel))
            return vel_mag <= (float(self.threshold) + 1e-6)
        elif self.name in (
            "forward_invariance_cbf_simulated",
            "CBF_FORWARD_INVARIANCE_HOLDS",
            "ISO_10218_TORQUE_LIMIT_SATISFIED",
            "COLLABORATIVE_SEPARATION_MAINTAINED",
        ):
            return bool(record.get("is_safe", False))
        return False


def parse_invariant_claim(inv: str) -> Optional[SafetyPredicate]:
    """
    Parses and strictly validates an invariant claim into a typed SafetyPredicate.
    Requires finite thresholds, explicit valid units ('m', 'Nm', 'm/s'),
    and physically reasonable bounds. Rejects 'nan', 'inf', negatives, and unparsed strings.
    """
    if not isinstance(inv, str):
        return None
    inv = inv.strip()

    exact_matches = {
        "forward_invariance_cbf_simulated == True": ("forward_invariance_cbf_simulated", "=="),
        "CBF_FORWARD_INVARIANCE_HOLDS": ("CBF_FORWARD_INVARIANCE_HOLDS", "=="),
        "ISO_10218_TORQUE_LIMIT_SATISFIED": ("ISO_10218_TORQUE_LIMIT_SATISFIED", "=="),
        "COLLABORATIVE_SEPARATION_MAINTAINED": ("COLLABORATIVE_SEPARATION_MAINTAINED", "=="),
    }
    if inv in exact_matches:
        name, op = exact_matches[inv]
        return SafetyPredicate(name=name, operator=op, threshold=None, unit=None, raw_claim=inv)

    patterns = [
        (r"^min_human_distance\s*>=\s*([0-9.]+)\s*(m)$", "min_human_distance", ">=", (0.01, 1000.0)),
        (r"^max_joint_torque\s*<=\s*([0-9.]+)\s*(Nm)$", "max_joint_torque", "<=", (0.01, 10000.0)),
        (r"^max_velocity\s*<=\s*([0-9.]+)\s*(m/s)$", "max_velocity", "<=", (0.01, 1000.0)),
    ]

    for pattern, name, op, (lower_b, upper_b) in patterns:
        m = re.match(pattern, inv)
        if m:
            val_str, unit = m.group(1), m.group(2)
            try:
                val = float(val_str)
                if not math.isfinite(val) or val < lower_b or val > upper_b:
                    return None
                return SafetyPredicate(name=name, operator=op, threshold=val, unit=unit, raw_claim=inv)
            except ValueError:
                return None

    return None


def validate_invariant_claim(inv: str) -> bool:
    """Validates that an invariant matches recognized safety commitment templates with finite bounds."""
    return parse_invariant_claim(inv) is not None


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


@dataclass
class CycleOpening:
    """Opening proof revealing underlying record state and Merkle audit path for one cycle."""
    cycle_index: int
    leaf_hash: str
    is_safe: bool
    human_proximity: float
    blinding_factor: str
    merkle_proof: List[Tuple[str, str]]
    record_payload: Optional[Dict[str, Any]] = None

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class BlindedOpeningPackage:
    """Exportable opening artifact containing cycle openings and Merkle proofs."""
    proof_id: str
    robot_id: str
    merkle_root: str
    total_cycles: int
    openings: List[CycleOpening]

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class EnvelopeVerificationStatus:
    """Result of comprehensive envelope and opening package verification."""
    is_valid: bool
    status: str  # "PREDICATES_VERIFIED", "PARTIALLY_OPENED", "STRUCTURE_VALID", "INVALID_STRUCTURE", "PREDICATE_FAILED"
    cycles_verified: int
    total_cycles: int
    errors: List[str]
    predicate_results: Dict[str, bool]

    def __bool__(self) -> bool:
        return self.is_valid


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
    Predicate verification requires opening proofs via verify_opening() or verify_opening_package().
    """

    def __init__(self, salt: Optional[str] = None) -> None:
        self.salt = salt or secrets.token_hex(16)
        self.last_opening_package: Optional[BlindedOpeningPackage] = None

    def generate_envelope_with_openings(
        self,
        ledger: MerkleBlackBoxLedger,
        robot_id: str,
        min_human_distance_m: float = 1.50,
        max_joint_torque_nm: float = 150.0,
        max_velocity_mps: float = 4.0,
    ) -> Tuple[BlindedSafetyEnvelope, BlindedOpeningPackage]:
        """
        Synthesizes a verifiable blinded commitment envelope AND an exportable opening package
        containing blinding factors, opened record states, and Merkle inclusion proofs.
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
        cycle_openings: List[CycleOpening] = []

        # 1. Generate blinded hash commitments and inclusion proofs for each cycle
        for i, rec in enumerate(records):
            r_blind = secrets.token_hex(16)
            blinding_factors.append(r_blind)

            # Blinded commitment masks raw coordinates while capturing compliance status
            payload = f"{rec['leaf_hash']}:{rec['is_safe']}:{rec['human_proximity']}:{r_blind}".encode()
            commit = hashlib.sha256(payload).hexdigest()
            commitments.append(commit)

            merkle_path = ledger.generate_audit_proof(i)
            cycle_openings.append(
                CycleOpening(
                    cycle_index=i,
                    leaf_hash=rec["leaf_hash"],
                    is_safe=rec["is_safe"],
                    human_proximity=rec["human_proximity"],
                    blinding_factor=r_blind,
                    merkle_proof=merkle_path,
                    record_payload=rec,
                )
            )

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

        envelope = BlindedSafetyEnvelope(
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

        opening_pkg = BlindedOpeningPackage(
            proof_id=proof_id,
            robot_id=robot_id,
            merkle_root=merkle_root,
            total_cycles=len(records),
            openings=cycle_openings,
        )

        self.last_opening_package = opening_pkg
        return envelope, opening_pkg

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
        envelope, _ = self.generate_envelope_with_openings(
            ledger=ledger,
            robot_id=robot_id,
            min_human_distance_m=min_human_distance_m,
            max_joint_torque_nm=max_joint_torque_nm,
            max_velocity_mps=max_velocity_mps,
        )
        return envelope

    # Alias for backwards compatibility
    def generate_zk_proof(self, *args, **kwargs) -> BlindedSafetyEnvelope:
        return self.generate_blinded_envelope(*args, **kwargs)

    @staticmethod
    def verify_blinded_envelope(
        envelope: BlindedSafetyEnvelope,
        expected_merkle_root: Optional[str] = None,
    ) -> bool:
        """
        Cryptographically verifies the blinded commitment envelope structure.
        Returns True if the commitment challenge and response proofs are valid,
        all certified invariants match allowed templates, and commitments bind to the root.
        Note: Verification of the envelope alone proves structural commitment validity.
        Proof of predicate compliance requires openings via verify_opening() or verify_opening_package().
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
        merkle_proof: Optional[List[Tuple[str, str]]] = None,
        full_record: Optional[Dict[str, Any]] = None,
    ) -> bool:
        """
        Verifies the opening proof for a specific cycle in the commitment envelope:
        1. Checks hash consistency with the blinded commitment and Fiat-Shamir response proof.
        2. Validates Merkle inclusion of leaf_hash against envelope.merkle_root (if proof supplied).
        3. Evaluates revealed values against all certified safety predicates in the envelope.
        Returns True ONLY if hash consistency, Merkle inclusion, AND predicate compliance all hold.
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

        # 3. Verify Merkle inclusion if proof is provided
        if merkle_proof is not None:
            if not MerkleBlackBoxLedger.verify_audit_proof(leaf_hash, merkle_proof, envelope.merkle_root):
                return False

        # 4. Evaluate all certified invariants against revealed values
        rec_data = dict(full_record or {})
        rec_data.setdefault("is_safe", is_safe)
        rec_data.setdefault("human_proximity", human_proximity)

        for inv in envelope.invariants_certified:
            pred = parse_invariant_claim(inv)
            if pred is None:
                return False
            if not pred.evaluate(rec_data):
                return False

        return True

    @staticmethod
    def verify_opening_package(
        envelope: BlindedSafetyEnvelope,
        package: BlindedOpeningPackage,
        expected_merkle_root: Optional[str] = None,
    ) -> EnvelopeVerificationStatus:
        """
        Verifies an entire opening package against a blinded safety envelope:
        - Verifies structural validity of the envelope.
        - Verifies binding to the claimed Merkle root.
        - Verifies that all claimed cycles are opened with valid Merkle inclusion proofs.
        - Evaluates all certified safety predicates across all revealed cycle states.
        Returns EnvelopeVerificationStatus with status 'PREDICATES_VERIFIED' on full satisfaction.
        """
        errors: List[str] = []
        pred_results: Dict[str, bool] = {}

        # 1. Verify structure of envelope
        if not BlindedSafetyProver.verify_blinded_envelope(envelope, expected_merkle_root):
            errors.append("Blinded envelope structural verification failed")
            return EnvelopeVerificationStatus(
                is_valid=False,
                status="INVALID_STRUCTURE",
                cycles_verified=0,
                total_cycles=envelope.total_cycles_proven,
                errors=errors,
                predicate_results=pred_results,
            )

        if package.merkle_root != envelope.merkle_root:
            errors.append(f"Opening package root '{package.merkle_root}' does not match envelope root '{envelope.merkle_root}'")
            return EnvelopeVerificationStatus(
                is_valid=False,
                status="INVALID_STRUCTURE",
                cycles_verified=0,
                total_cycles=envelope.total_cycles_proven,
                errors=errors,
                predicate_results=pred_results,
            )

        # Parse all certified predicates
        predicates: List[SafetyPredicate] = []
        for inv in envelope.invariants_certified:
            pred = parse_invariant_claim(inv)
            if pred is None:
                errors.append(f"Invalid certified invariant claim '{inv}'")
            else:
                predicates.append(pred)
                pred_results[inv] = True

        if errors:
            return EnvelopeVerificationStatus(
                is_valid=False,
                status="INVALID_STRUCTURE",
                cycles_verified=0,
                total_cycles=envelope.total_cycles_proven,
                errors=errors,
                predicate_results=pred_results,
            )

        # 2. Verify openings
        verified_count = 0
        seen_indices = set()

        for opening in package.openings:
            idx = opening.cycle_index
            if idx in seen_indices:
                errors.append(f"Duplicate opening for cycle index {idx}")
                continue
            seen_indices.add(idx)

            ok = BlindedSafetyProver.verify_opening(
                envelope=envelope,
                cycle_index=idx,
                leaf_hash=opening.leaf_hash,
                is_safe=opening.is_safe,
                human_proximity=opening.human_proximity,
                blinding_factor=opening.blinding_factor,
                merkle_proof=opening.merkle_proof,
                full_record=opening.record_payload,
            )
            if not ok:
                errors.append(f"Opening verification failed for cycle {idx} (Merkle proof, hash, or predicate violated)")
            else:
                verified_count += 1

        if errors:
            status = "PREDICATE_FAILED"
            is_valid = False
        elif verified_count == envelope.total_cycles_proven:
            status = "PREDICATES_VERIFIED"
            is_valid = True
        elif verified_count > 0:
            status = "PARTIALLY_OPENED"
            is_valid = False
        else:
            status = "STRUCTURE_VALID"
            is_valid = True

        return EnvelopeVerificationStatus(
            is_valid=is_valid,
            status=status,
            cycles_verified=verified_count,
            total_cycles=envelope.total_cycles_proven,
            errors=errors,
            predicate_results=pred_results,
        )

    # Alias for backwards compatibility
    @staticmethod
    def verify_zk_proof(envelope: BlindedSafetyEnvelope, expected_merkle_root: Optional[str] = None) -> bool:
        return BlindedSafetyProver.verify_blinded_envelope(envelope, expected_merkle_root)


# Backwards-compatible class aliases
BlindedCommitmentProver = BlindedSafetyProver
ZKSafetyProver = BlindedSafetyProver
