"""
Physical AI Governor: Autonomous Physical AI, Humanoid (GR00T) & Drone Swarm GRC Assurance Engine.
Enforces continuous Control Barrier Functions (CBF, QP-CBF, HOCBF) over streaming ROS 2, MAVLink,
and VLA joint trajectories, notarizing tamper-evident black-box Merkle ledgers and compliance passports
for FAA Part 89, EU AI Act Annex III, and ISO 10218 / ISO/TS 15066.
"""

from .control_barrier import (
    ControlBarrierFilter,
    HighOrderControlBarrierFilter,
    HumanoidStabilityGovernor,
    HumanoidStabilityState,
    QPSafetyFilter,
    SafetyDecision,
)
from .evaluator import PhysicalAIBenchmarkRunner
from .mavlink_frame import (
    MAVLinkFrameParser,
    MAVLinkV2Message,
    calculate_mavlink_crc,
    serialize_mavlink_v2_global_position,
)
from .merkle_blackbox import CompliancePassport, MerkleBlackBoxLedger
from .qp_solver import ActiveSetQPSolver, QPSolution
from .statutory_engine import (
    ISO15066_BIOMECHANICAL_LIMITS_N,
    RemoteIDLocationPayload,
    StatutoryAssuranceEngine,
)
from .telemetry_ingest import RobotTelemetryPacket, TelemetryIngestor
from .vla_validator import VLAActionHorizonValidator, VLAChunkValidationResult

__all__ = [
    # Telemetry
    "TelemetryIngestor",
    "RobotTelemetryPacket",
    "MAVLinkFrameParser",
    "MAVLinkV2Message",
    "serialize_mavlink_v2_global_position",
    "calculate_mavlink_crc",
    # Control Barrier Functions
    "ControlBarrierFilter",
    "QPSafetyFilter",
    "HighOrderControlBarrierFilter",
    "HumanoidStabilityGovernor",
    "HumanoidStabilityState",
    "SafetyDecision",
    # Optimization
    "ActiveSetQPSolver",
    "QPSolution",
    # VLA
    "VLAActionHorizonValidator",
    "VLAChunkValidationResult",
    # Ledger & Passports
    "MerkleBlackBoxLedger",
    "CompliancePassport",
    # Statutory & Assurance
    "StatutoryAssuranceEngine",
    "RemoteIDLocationPayload",
    "ISO15066_BIOMECHANICAL_LIMITS_N",
    # Benchmark
    "PhysicalAIBenchmarkRunner",
]
