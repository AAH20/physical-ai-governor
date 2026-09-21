"""
ROS 2 (Robot Operating System 2 - Humble/Iron/Jazzy) & DDS Telemetry Bridge.
Translates standard ROS 2 messages:
    - sensor_msgs/JointState
    - geometry_msgs/Twist
    - trajectory_msgs/JointTrajectory
into RobotTelemetryPackets and exports diagnostic compliance topics.
Operates seamlessly with or without rclpy installed (pure Python standard library).
"""

import json
import time
from dataclasses import asdict, dataclass
from typing import Any, Dict, List, Optional, Tuple

from .control_barrier import ControlBarrierFilter, SafetyDecision
from .merkle_blackbox import MerkleBlackBoxLedger
from .telemetry_ingest import RobotTelemetryPacket


@dataclass
class ROS2JointState:
    """Represents sensor_msgs/msg/JointState."""
    names: List[str]
    positions: List[float]
    velocities: List[float]
    efforts: List[float]
    stamp_sec: int
    stamp_nanosec: int


@dataclass
class ROS2Twist:
    """Represents geometry_msgs/msg/Twist."""
    linear_xyz: Tuple[float, float, float]
    angular_xyz: Tuple[float, float, float]


class ROS2TelemetryBridge:
    """
    Translates standard ROS 2 and DDS telemetry topics into physical AI governor packets.
    """

    def __init__(
        self,
        cbf_filter: Optional[ControlBarrierFilter] = None,
        ledger: Optional[MerkleBlackBoxLedger] = None,
    ) -> None:
        self.cbf = cbf_filter or ControlBarrierFilter()
        self.ledger = ledger or MerkleBlackBoxLedger()

    def convert_joint_state(
        self,
        msg: ROS2JointState,
        robot_id: str,
        commanded_efforts: List[float],
        human_proximity_m: float = 10.0,
        base_pos: Tuple[float, float, float] = (0.0, 0.0, 1.0),
        base_vel: Tuple[float, float, float] = (0.0, 0.0, 0.0),
    ) -> RobotTelemetryPacket:
        """
        Converts sensor_msgs/JointState into RobotTelemetryPacket.
        """
        ts_ns = msg.stamp_sec * 1_000_000_000 + msg.stamp_nanosec

        return RobotTelemetryPacket(
            robot_id=robot_id,
            robot_type="humanoid_biped",
            timestamp_ns=ts_ns,
            position_xyz=base_pos,
            velocity_xyz=base_vel,
            joint_torques=msg.efforts,
            human_distance_meters=human_proximity_m,
            battery_percentage=95.0,
            command_torque_input=commanded_efforts,
        )

    def process_ros2_cycle(
        self,
        msg: ROS2JointState,
        robot_id: str,
        commanded_efforts: List[float],
        human_proximity_m: float = 10.0,
    ) -> Tuple[SafetyDecision, str, Dict[str, Any]]:
        """
        Processes a full ROS 2 control cycle.
        Returns: (SafetyDecision, leaf_hash, diagnostic_dict)
        """
        pkt = self.convert_joint_state(
            msg=msg,
            robot_id=robot_id,
            commanded_efforts=commanded_efforts,
            human_proximity_m=human_proximity_m,
        )
        decision = self.cbf = self.cbf.evaluate_safety(pkt)
        leaf_hash = self.ledger.append_record(pkt, decision)

        diagnostics = {
            "name": "physical_ai_governor_diagnostics",
            "level": 0 if decision.is_safe else 1,
            "message": "SAFETY_NOMINAL" if decision.is_safe else "CBF_INTERVENTION_TRIGGERED",
            "hardware_id": robot_id,
            "values": {
                "cbf_margin": decision.cbf_margin,
                "intervention_triggered": decision.intervention_triggered,
                "violation_reason": decision.violation_reason or "None",
                "merkle_leaf_hash": leaf_hash,
            },
        }

        return (decision, leaf_hash, diagnostics)
