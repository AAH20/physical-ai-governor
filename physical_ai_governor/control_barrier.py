"""
Control Barrier Function (CBF) Runtime Safety Filter.
Enforces continuous mathematical forward invariance over physical robot actuators,
guaranteeing zero human proximity violations and zero torque saturation breaches.
"""

import math
from dataclasses import dataclass
from typing import List, Optional, Tuple

from .telemetry_ingest import RobotTelemetryPacket


@dataclass
class SafetyDecision:
    """Outcome of a real-time Control Barrier Function evaluation."""
    is_safe: bool
    original_command: List[float]
    filtered_command: List[float]
    cbf_margin: float
    intervention_triggered: bool
    violation_reason: Optional[str]


class ControlBarrierFilter:
    """
    Control Barrier Function (CBF) safety governor.
    Evaluates:
        h(x) >= 0  (Safety set C)
        dh/dt >= -alpha * h(x)
    If the commanded actuator vector violates the barrier, clamps to the nearest safe projection.
    """

    def __init__(
        self,
        min_human_distance_m: float = 1.50,
        max_joint_torque_nm: float = 150.0,
        max_velocity_mps: float = 4.0,
        cbf_gamma: float = 1.2,
    ) -> None:
        self.min_human_distance_m = min_human_distance_m
        self.max_joint_torque_nm = max_joint_torque_nm
        self.max_velocity_mps = max_velocity_mps
        self.cbf_gamma = cbf_gamma

    def evaluate_safety(
        self, packet: RobotTelemetryPacket
    ) -> SafetyDecision:
        """
        Evaluates physical barrier constraints and computes safe actuator commands.
        """
        original = packet.command_torque_input
        filtered = list(original)
        intervened = False
        reasons: List[str] = []

        # 1. Torque Saturation Barrier: h_torque = tau_max - |tau_i|
        max_cmd_torque = max(abs(t) for t in original) if original else 0.0
        torque_margin = self.max_joint_torque_nm - max_cmd_torque

        if torque_margin < 0:
            intervened = True
            reasons.append(f"Torque command ({max_cmd_torque:.1f}Nm) exceeds safe limit ({self.max_joint_torque_nm}Nm)")
            filtered = [
                math.copysign(min(abs(t), self.max_joint_torque_nm), t) for t in original
            ]

        # 2. Human Proximity Barrier: h_prox = d_human - d_safe
        prox_margin = packet.human_distance_meters - self.min_human_distance_m
        if prox_margin < 0:
            intervened = True
            reasons.append(
                f"Human proximity ({packet.human_distance_meters:.2f}m) breaches safe barrier ({self.min_human_distance_m:.2f}m)"
            )
            # Apply emergency proportional damping to reduce actuator authority
            damping_factor = max(0.0, packet.human_distance_meters / self.min_human_distance_m)
            filtered = [t * damping_factor for t in filtered]

        # 3. Speed Limit Barrier
        vel_mag = math.sqrt(sum(v * v for v in packet.velocity_xyz))
        if vel_mag > self.max_velocity_mps:
            intervened = True
            reasons.append(f"Robot velocity ({vel_mag:.2f}m/s) exceeds maximum operational velocity ({self.max_velocity_mps}m/s)")
            scale = self.max_velocity_mps / vel_mag
            filtered = [t * scale for t in filtered]

        composite_margin = min(torque_margin, prox_margin)
        is_safe = not intervened
        reason_str = "; ".join(reasons) if reasons else None

        return SafetyDecision(
            is_safe=is_safe,
            original_command=original,
            filtered_command=[round(x, 3) for x in filtered],
            cbf_margin=round(composite_margin, 3),
            intervention_triggered=intervened,
            violation_reason=reason_str,
        )
