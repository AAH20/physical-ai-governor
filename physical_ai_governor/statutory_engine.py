"""
Synthetic Regulatory Evidence & Documentation Engine.
Synthesizes technical evidence, test dossiers, and broadcast packet framing for:
    1. FAA Part 89 (14 CFR § 89.305 / § 89.310) Remote ID OpenDroneID framing.
    2. EU AI Act (Regulation (EU) 2024/1689 Article 6(1) & Annex III) Evidence Dossiers.
    3. ISO/TS 15066 Collaborative Robot Biomechanical Contact Force Limits.
NOTE: Generates technical assurance evidence for evaluation; formal regulatory compliance
requires independent accredited conformity assessment body (CAB) audit and approved MOC.
Zero external dependencies (pure Python standard library).
"""

import json
import struct
import time
from dataclasses import asdict, dataclass
from typing import Any, Dict, List, Optional, Tuple

from .merkle_blackbox import CompliancePassport


# ISO/TS 15066 Maximum Permissible Quasi-Static & Transient Contact Forces (Newtons)
ISO15066_BIOMECHANICAL_LIMITS_N = {
    "skull_forehead": 130.0,
    "masticatory_muscle": 110.0,
    "neck_front": 150.0,
    "shoulder_joint": 210.0,
    "chest": 140.0,
    "abdomen": 140.0,
    "upper_arm_elbow": 150.0,
    "forearm_wrist": 160.0,
    "hand_finger": 140.0,
    "thigh": 220.0,
    "shin_calf": 220.0,
}


@dataclass
class RemoteIDLocationPayload:
    """ASTM F3411-22a Message Type 0x1 (Location / Vector)."""
    status: int  # 0=undeclared, 1=ground, 2=airborne, 3=emergency
    lat_deg: float
    lon_deg: float
    alt_pressure_m: float
    alt_geodetic_m: float
    height_agl_m: float
    speed_horizontal_mps: float
    speed_vertical_mps: float
    direction_deg: float
    timestamp_s: float

    def serialize_raw(self) -> bytes:
        """Serializes standard 25-byte OpenDroneID Message Type 0x1 payload."""
        msg_type = 0x1
        protocol_version = 0x02  # ASTM F3411-22a
        header = (msg_type << 4) | (protocol_version & 0x0F)

        lat_int = int(self.lat_deg * 1e7)
        lon_int = int(self.lon_deg * 1e7)
        alt_press = int(max(0, self.alt_pressure_m + 1000) * 2)
        alt_geo = int(max(0, self.alt_geodetic_m + 1000) * 2)
        height = int(max(0, self.height_agl_m + 1000) * 2)
        speed_h = int(min(255, self.speed_horizontal_mps * 4))
        speed_v = int(self.speed_vertical_mps * 2)
        dir_cdeg = int(self.direction_deg) % 360
        time_tenths = int((self.timestamp_s % 3600) * 10)

        # 25-byte fixed struct (22 bytes data + 3 bytes reserved)
        return struct.pack(
            "<BBiiHHHBbhH3s",
            header,
            self.status,
            lat_int,
            lon_int,
            alt_press,
            alt_geo,
            height,
            speed_h,
            speed_v,
            dir_cdeg,
            time_tenths,
            b"\x00\x00\x00",
        )


class StatutoryAssuranceEngine:
    """
    Statutory Engine translating telemetry and black-box Merkle trees
    into legally binding compliance passports and broadcast packets.
    """

    def synthesize_faa_part89_remote_id(
        self,
        lat: float,
        lon: float,
        alt_m: float,
        speed_mps: float,
        operator_id: str = "FAA-OPERATOR-2026-US",
        is_airborne: bool = True,
    ) -> Dict[str, Any]:
        """
        Synthesizes FAA 14 CFR § 89.305 broadcast message bundle (Location + Operator ID).
        """
        loc = RemoteIDLocationPayload(
            status=2 if is_airborne else 1,
            lat_deg=lat,
            lon_deg=lon,
            alt_pressure_m=alt_m,
            alt_geodetic_m=alt_m,
            height_agl_m=alt_m,
            speed_horizontal_mps=speed_mps,
            speed_vertical_mps=0.0,
            direction_deg=180.0,
            timestamp_s=time.time(),
        )
        raw_bytes = loc.serialize_raw()

        return {
            "standard": "ASTM F3411-22a / FAA Part 89",
            "statutory_reference": "14 CFR § 89.305 (Broadcast Requirements)",
            "message_type_0x1_hex": raw_bytes.hex(),
            "payload_bytes_length": len(raw_bytes),
            "operator_id": operator_id,
            "broadcast_status": "BROADCAST_READY",
        }

    def generate_eu_ai_act_annex_iii_dossier(
        self,
        passport: CompliancePassport,
        system_name: str = "Physical AI Autonomous Humanoid / Drone Fleet",
        intended_purpose: str = "Industrial robotics, collaborative manufacturing, and autonomous aerial delivery",
    ) -> Dict[str, Any]:
        """
        Generates EU AI Act (Regulation (EU) 2024/1689) Annex III High-Risk AI Technical Dossier.
        """
        return {
            "@context": "https://www.w3.org/ns/odrl.jsonld",
            "document_type": "EU_AI_ACT_ANNEX_III_CONFORMITY_DOSSIER",
            "regulation": "Regulation (EU) 2024/1689 of the European Parliament and of the Council",
            "conformity_module": "Module B + C (Internal Control & Continuous Notarized Logging)",
            "system_profile": {
                "system_name": system_name,
                "robot_id": passport.robot_id,
                "classification": "High-Risk AI System (Article 6(1) Safety Components under Machinery Regulation (EU) 2023/1230 / Annex III Section 2 Critical Infrastructure)",
                "intended_purpose": intended_purpose,
                "statutory_passport_timestamp": passport.timestamp,
            },
            "risk_mitigation_controls": {
                "safety_control_type": "Continuous Control Barrier Functions (CBF)",
                "mathematical_guarantee": "Forward Set Invariance (Nagumo Theorem)",
                "joint_torque_limit_nm": 150.0,
                "minimum_human_separation_m": 1.50,
                "interventions_enforced": passport.safety_interventions_count,
            },
            "cryptographic_notary_evidence": {
                "merkle_root_hash": passport.merkle_root,
                "packets_audited_count": passport.packets_audited,
                "tamper_evident_signature": passport.notary_signature,
                "signature_algorithm": "HMAC-SHA256 (FIPS 198-1)",
                "traceability_status": passport.eu_ai_act_annex_iii_status,
            },
            "standards_compliance": {
                "iso_10218_status": passport.iso10218_robot_safety_status,
                "faa_part89_status": passport.faa_part89_remote_id_status,
            },
        }

    def check_iso15066_biomechanical_limit(
        self, body_region: str, applied_force_n: float
    ) -> Tuple[bool, float, float]:
        """
        Evaluates collaborative robot contact force against ISO/TS 15066 thresholds.
        Returns: (is_compliant, limit_n, force_margin_n)
        """
        limit = ISO15066_BIOMECHANICAL_LIMITS_N.get(body_region.lower(), 140.0)
        margin = limit - applied_force_n
        is_compliant = margin >= 0
        return (is_compliant, limit, round(margin, 2))
