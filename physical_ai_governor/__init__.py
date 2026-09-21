"""
Physical AI Governor: Autonomous Physical AI, Humanoid (GR00T) & Drone Swarm GRC Assurance Engine.
Enforces continuous Control Barrier Functions (CBF, QP-CBF, HOCBF) over streaming ROS 2, MAVLink,
and VLA joint trajectories, notarizing tamper-evident black-box Merkle ledgers and compliance passports
for FAA Part 89, EU AI Act Annex III, ISO 10218 / ISO/TS 15066, GRC_Claw (ISO 42001), TPM 2.0, and ZK proofs.
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
from .grc_claw_bridge import (
    GRCClawBridge,
    GRCClawEvidenceRecord,
    canonical_json,
    compute_canonical_digest,
)
from .hardware_tpm import TPM2HardwareAttestor, TPMQuote
from .mavlink_frame import (
    MAVLinkFrameParser,
    MAVLinkV2Message,
    calculate_mavlink_crc,
    serialize_mavlink_v2_global_position,
)
from .merkle_blackbox import CompliancePassport, MerkleBlackBoxLedger
from .qp_solver import ActiveSetQPSolver, QPSolution
from .ros2_bridge import ROS2JointState, ROS2TelemetryBridge, ROS2Twist
from .safety_state_machine import (
    ISO10218SafetyStateMachine,
    RobotSafetyState,
    StateTransitionRecord,
)
from .statutory_engine import (
    ISO15066_BIOMECHANICAL_LIMITS_N,
    RemoteIDLocationPayload,
    StatutoryAssuranceEngine,
)
from .swarm_cbf import (
    SwarmAgentState,
    SwarmControlBarrierGovernor,
    SwarmSafetyDecision,
)
from .telemetry_ingest import RobotTelemetryPacket, TelemetryIngestor
from .telemetry_stream import TelemetryStreamServer
from .vla_validator import VLAActionHorizonValidator, VLAChunkValidationResult
from .zk_proof import ZKSafetyProofEnvelope, ZKSafetyProver

__all__ = [
    # Telemetry, ROS 2 & Streaming
    "TelemetryIngestor",
    "RobotTelemetryPacket",
    "MAVLinkFrameParser",
    "MAVLinkV2Message",
    "serialize_mavlink_v2_global_position",
    "calculate_mavlink_crc",
    "TelemetryStreamServer",
    "ROS2TelemetryBridge",
    "ROS2JointState",
    "ROS2Twist",
    # Control Barrier Functions & Safety State Machine
    "ControlBarrierFilter",
    "QPSafetyFilter",
    "HighOrderControlBarrierFilter",
    "HumanoidStabilityGovernor",
    "HumanoidStabilityState",
    "ISO10218SafetyStateMachine",
    "RobotSafetyState",
    "StateTransitionRecord",
    "SafetyDecision",
    # Swarm
    "SwarmControlBarrierGovernor",
    "SwarmAgentState",
    "SwarmSafetyDecision",
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
    # GRC_Claw Bridge
    "GRCClawBridge",
    "GRCClawEvidenceRecord",
    "canonical_json",
    "compute_canonical_digest",
    # Hardware TPM & ZK
    "TPM2HardwareAttestor",
    "TPMQuote",
    "ZKSafetyProver",
    "ZKSafetyProofEnvelope",
    # Benchmark
    "PhysicalAIBenchmarkRunner",
]
