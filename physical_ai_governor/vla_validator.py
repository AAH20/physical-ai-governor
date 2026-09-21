"""
Vision-Language-Action (VLA) Horizon Safety Validator.
Evaluates multi-step action chunks from models like OpenVLA, Octo, and RT-2.
Screens the entire trajectory horizon H (e.g. 8 to 16 steps) for Control Barrier Function
forward invariance before actuator dispatch, synthesizing proactive deceleration when needed.
"""

import math
from dataclasses import dataclass, field
from typing import List, Optional, Tuple

from .control_barrier import ControlBarrierFilter, SafetyDecision
from .telemetry_ingest import RobotTelemetryPacket


@dataclass
class VLAChunkValidationResult:
    """Outcome of validating a predicted multi-step action chunk."""
    is_chunk_safe: bool
    horizon_steps: int
    first_violation_step: Optional[int]
    violation_reasons: List[str]
    original_action_chunk: List[List[float]]
    safe_action_chunk: List[List[float]]
    min_predicted_cbf_margin: float


class VLAActionHorizonValidator:
    """
    Validates and filters multi-step action trajectory predictions from VLA models.
    """

    def __init__(
        self,
        dt_seconds: float = 0.05,
        min_human_distance_m: float = 1.50,
        max_joint_torque_nm: float = 150.0,
        max_velocity_mps: float = 3.0,
    ) -> None:
        self.dt = dt_seconds
        self.min_human_dist = min_human_distance_m
        self.max_torque = max_joint_torque_nm
        self.max_vel = max_velocity_mps
        self.cbf_filter = ControlBarrierFilter(
            min_human_distance_m=min_human_distance_m,
            max_joint_torque_nm=max_joint_torque_nm,
            max_velocity_mps=max_velocity_mps,
        )

    def validate_and_filter_chunk(
        self,
        initial_packet: RobotTelemetryPacket,
        action_chunk: List[List[float]],
    ) -> VLAChunkValidationResult:
        """
        Simulates action execution over the horizon H.
        If any step breaches the barrier, generates a safe decelerated chunk.
        """
        horizon = len(action_chunk)
        if horizon == 0:
            return VLAChunkValidationResult(
                is_chunk_safe=True,
                horizon_steps=0,
                first_violation_step=None,
                violation_reasons=[],
                original_action_chunk=[],
                safe_action_chunk=[],
                min_predicted_cbf_margin=1.0,
            )

        cur_pos = list(initial_packet.position_xyz)
        cur_vel = list(initial_packet.velocity_xyz)
        cur_dist = initial_packet.human_distance_meters

        reasons: List[str] = []
        first_violation: Optional[int] = None
        min_margin = float("inf")

        safe_chunk: List[List[float]] = []

        for step, u_cmd in enumerate(action_chunk):
            # 1. Check torque limits
            max_torque = max(abs(t) for t in u_cmd) if u_cmd else 0.0
            torque_margin = self.max_torque - max_torque

            # 2. Predict next state under simple discrete dynamics
            # Assuming simplified 1 kg-m^2 effective joint inertia for forward estimation
            acc_estimate = [t * 0.05 for t in u_cmd]
            next_vel = [
                v + a * self.dt for v, a in zip(cur_vel, acc_estimate + [0.0] * (3 - len(acc_estimate)))
            ][:3]
            speed = math.sqrt(sum(v * v for v in next_vel))

            # Approximation: if moving along velocity vector toward human, distance closes
            next_dist = max(0.0, cur_dist - speed * self.dt)
            prox_margin = next_dist - self.min_human_dist

            step_margin = min(torque_margin, prox_margin)
            if step_margin < min_margin:
                min_margin = step_margin

            # Create synthetic packet for step
            step_pkt = RobotTelemetryPacket(
                robot_id=initial_packet.robot_id,
                robot_type=initial_packet.robot_type,
                timestamp_ns=initial_packet.timestamp_ns + int((step + 1) * self.dt * 1e9),
                position_xyz=tuple(cur_pos),
                velocity_xyz=tuple(next_vel),
                joint_torques=u_cmd,
                human_distance_meters=next_dist,
                battery_percentage=initial_packet.battery_percentage,
                command_torque_input=u_cmd,
            )

            decision = self.cbf_filter.evaluate_safety(step_pkt)

            if not decision.is_safe:
                if first_violation is None:
                    first_violation = step
                reasons.append(f"Step {step}: {decision.violation_reason}")
                safe_chunk.append(decision.filtered_command)
            else:
                safe_chunk.append(list(u_cmd))

            # Advance state
            cur_pos = [p + v * self.dt for p, v in zip(cur_pos, next_vel)]
            cur_vel = next_vel
            cur_dist = next_dist

        is_safe = (first_violation is None)

        return VLAChunkValidationResult(
            is_chunk_safe=is_safe,
            horizon_steps=horizon,
            first_violation_step=first_violation,
            violation_reasons=reasons,
            original_action_chunk=action_chunk,
            safe_action_chunk=safe_chunk,
            min_predicted_cbf_margin=round(min_margin, 3),
        )
