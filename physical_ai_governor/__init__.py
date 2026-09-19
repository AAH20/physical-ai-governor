"""
Physical AI Governor: Autonomous Physical AI, Humanoid (GR00T) & Drone Swarm GRC Assurance Engine.
Enforces continuous Control Barrier Functions (CBF) over streaming ROS 2, MAVLink,
and VLA joint trajectories, notarizing tamper-evident black-box Merkle ledgers and compliance passports
for FAA Part 89 and EU AI Act Annex III.
"""

from .telemetry_ingest import TelemetryIngestor, RobotTelemetryPacket
from .control_barrier import ControlBarrierFilter, SafetyDecision
from .merkle_blackbox import MerkleBlackBoxLedger, CompliancePassport
from .evaluator import PhysicalAIBenchmarkRunner

__all__ = [
    "TelemetryIngestor",
    "RobotTelemetryPacket",
    "ControlBarrierFilter",
    "SafetyDecision",
    "MerkleBlackBoxLedger",
    "CompliancePassport",
    "PhysicalAIBenchmarkRunner",
]
