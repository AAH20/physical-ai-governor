"""
Merkle Black-Box Audit Ledger & Statutory Compliance Passports.
Constructs immutable streaming Merkle trees over physical AI telemetry,
generates cryptographic inclusion proofs for individual flight/actuator decisions,
and issues synthetic evidence passports for FAA Part 89 Remote ID,
EU AI Act Annex III, and ISO 10218.
"""

import hashlib
import hmac
import json
import time
from dataclasses import asdict, dataclass
from typing import Any, Dict, List, Optional, Tuple

from .control_barrier import SafetyDecision
from .telemetry_ingest import RobotTelemetryPacket


@dataclass
class CompliancePassport:
    """Synthetic evidence passport reflecting local deterministic CBF and telemetry simulation results."""
    robot_id: str
    merkle_root: str
    packets_audited: int
    safety_interventions_count: int
    faa_part89_remote_id_status: str
    eu_ai_act_annex_iii_status: str
    iso10218_robot_safety_status: str
    notary_signature: str
    timestamp: float

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


class MerkleBlackBoxLedger:
    """
    Continuous streaming flight/actuator recorder.
    Hashes telemetry into cryptographic Merkle blocks to ensure immutable post-incident forensics.
    Provides inclusion proofs and verification for statutory audits.
    """

    def __init__(self, signing_key: str = "a2z-physical-ai-notary-key-2026") -> None:
        self.signing_key = signing_key.encode("utf-8")
        self.leaf_hashes: List[str] = []
        self.records: List[Dict[str, Any]] = []

    def compute_packet_hash(
        self, packet: RobotTelemetryPacket, decision: SafetyDecision
    ) -> str:
        """Computes SHA-256 digest of physical state and safety filter decision."""
        payload = (
            f"{packet.robot_id}:{packet.timestamp_ns}:{packet.position_xyz}:"
            f"{packet.velocity_xyz}:{packet.human_distance_meters}:{decision.is_safe}:"
            f"{decision.filtered_command}"
        ).encode("utf-8")
        return hashlib.sha256(payload).hexdigest()

    def append_record(
        self, packet: RobotTelemetryPacket, decision: SafetyDecision
    ) -> str:
        """Appends a single telemetry record to the in-memory black-box ledger."""
        leaf = self.compute_packet_hash(packet, decision)
        self.leaf_hashes.append(leaf)
        self.records.append({
            "leaf_hash": leaf,
            "robot_id": packet.robot_id,
            "timestamp_ns": packet.timestamp_ns,
            "position": list(packet.position_xyz),
            "velocity": list(packet.velocity_xyz),
            "human_proximity": packet.human_distance_meters,
            "is_safe": decision.is_safe,
            "original_command": decision.original_command,
            "filtered_command": decision.filtered_command,
            "violation_reason": decision.violation_reason,
        })
        return leaf

    def build_merkle_root(self) -> str:
        """
        Constructs balanced binary Merkle tree root over accumulated leaves.
        """
        if not self.leaf_hashes:
            return hashlib.sha256(b"empty_ledger").hexdigest()

        current_level = list(self.leaf_hashes)
        while len(current_level) > 1:
            next_level = []
            for i in range(0, len(current_level), 2):
                left = current_level[i]
                right = current_level[i + 1] if i + 1 < len(current_level) else left
                combined = hashlib.sha256(f"{left}:{right}".encode()).hexdigest()
                next_level.append(combined)
            current_level = next_level

        return current_level[0]

    def generate_audit_proof(self, index: int) -> List[Tuple[str, str]]:
        """
        Generates Merkle audit proof path for leaf at `index`.
        Returns list of tuples: (sibling_hash, sibling_position: 'left' | 'right').
        """
        if index < 0 or index >= len(self.leaf_hashes):
            raise IndexError(f"Leaf index {index} out of bounds (total leaves: {len(self.leaf_hashes)})")

        proof: List[Tuple[str, str]] = []
        current_level = list(self.leaf_hashes)
        idx = index

        while len(current_level) > 1:
            next_level = []
            for i in range(0, len(current_level), 2):
                left = current_level[i]
                right = current_level[i + 1] if i + 1 < len(current_level) else left

                if i == idx:
                    # Current node is left, sibling is right
                    proof.append((right, "right"))
                elif i + 1 == idx:
                    # Current node is right, sibling is left
                    proof.append((left, "left"))

                combined = hashlib.sha256(f"{left}:{right}".encode()).hexdigest()
                next_level.append(combined)

            idx //= 2
            current_level = next_level

        return proof

    @staticmethod
    def verify_audit_proof(
        leaf_hash: str,
        proof: List[Tuple[str, str]],
        expected_root: str,
    ) -> bool:
        """
        Cryptographically verifies that leaf_hash belongs to the tree with expected_root.
        """
        current_hash = leaf_hash
        for sibling_hash, direction in proof:
            if direction == "left":
                combined = f"{sibling_hash}:{current_hash}"
            else:
                combined = f"{current_hash}:{sibling_hash}"
            current_hash = hashlib.sha256(combined.encode()).hexdigest()

        return current_hash == expected_root

    def issue_compliance_passport(
        self,
        robot_id: str,
        total_interventions: int,
    ) -> CompliancePassport:
        """
        Issues an institutional compliance passport backed by the Merkle root.
        """
        now = time.time()
        merkle_root = self.build_merkle_root()

        # Sign passport
        payload = f"{robot_id}:{merkle_root}:{len(self.leaf_hashes)}:{total_interventions}:{now}".encode("utf-8")
        sig = hmac.new(self.signing_key, payload, hashlib.sha256).hexdigest()

        return CompliancePassport(
            robot_id=robot_id,
            merkle_root=merkle_root,
            packets_audited=len(self.leaf_hashes),
            safety_interventions_count=total_interventions,
            faa_part89_remote_id_status="FAA_MOC_DOC_REQUIRED",
            eu_ai_act_annex_iii_status="CONTROL_EVIDENCE_GENERATED",
            iso10218_robot_safety_status="SYNTHETIC_TEST_PASSED",
            notary_signature=sig,
            timestamp=now,
        )

    def export_json(self) -> str:
        """Exports black-box ledger audit records and root as JSON."""
        return json.dumps(
            {
                "merkle_root": self.build_merkle_root(),
                "total_records": len(self.records),
                "records": self.records,
            },
            indent=2,
        )
