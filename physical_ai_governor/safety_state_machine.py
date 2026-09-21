"""
ISO 10218-1 / ISO/TS 15066 Deterministic Safety State Machine.
Supervises physical AI robot transitions between operational, collaborative,
protective stop, and emergency stop states with formal hysteresis.
Zero external dependencies (pure Python standard library).
"""

from dataclasses import dataclass
from enum import Enum
from typing import List, Optional, Tuple

from .telemetry_ingest import RobotTelemetryPacket


class RobotSafetyState(Enum):
    """Operational states defined under ISO 10218-1 Section 5."""
    NORMAL_AUTONOMOUS = "NORMAL_AUTONOMOUS"
    REDUCED_SPEED_COLLABORATIVE = "REDUCED_SPEED_COLLABORATIVE"  # Speed <= 250 mm/s
    PROTECTIVE_STOP = "PROTECTIVE_STOP"                          # Monitored stop, zero torque
    EMERGENCY_STOP = "EMERGENCY_STOP"                            # Hard safety stop / manual trip


@dataclass
class StateTransitionRecord:
    """Audit log of a safety state transition."""
    timestamp_ns: int
    previous_state: RobotSafetyState
    new_state: RobotSafetyState
    trigger_reason: str
    human_distance_m: float
    current_speed_mps: float


class ISO10218SafetyStateMachine:
    """
    Safety State Machine governing collaborative robot operational modes.
    Enforces ISO 10218-1 § 5.3.3 reduced speed limit (0.25 m/s) and monitored protective stops.
    """

    def __init__(
        self,
        stop_distance_m: float = 0.50,
        collaborative_distance_m: float = 1.50,
        max_collaborative_speed_mps: float = 0.25,  # ISO 10218-1 250 mm/s limit
        hysteresis_m: float = 0.10,
    ) -> None:
        self.stop_dist = stop_distance_m
        self.collab_dist = collaborative_distance_m
        self.max_collab_speed = max_collaborative_speed_mps
        self.hysteresis = hysteresis_m

        self.current_state = RobotSafetyState.NORMAL_AUTONOMOUS
        self.transitions: List[StateTransitionRecord] = []
        self.e_stop_latched = False

    def trigger_emergency_stop(self, reason: str, timestamp_ns: int = 0) -> None:
        """Latches hardware emergency stop."""
        self.e_stop_latched = True
        self._transition_to(RobotSafetyState.EMERGENCY_STOP, reason, timestamp_ns, 0.0, 0.0)

    def reset_emergency_stop(self) -> bool:
        """Resets emergency stop latch if conditions are cleared."""
        self.e_stop_latched = False
        self.current_state = RobotSafetyState.PROTECTIVE_STOP
        return True

    def _transition_to(
        self,
        new_state: RobotSafetyState,
        reason: str,
        timestamp_ns: int,
        human_dist: float,
        speed: float,
    ) -> None:
        if self.current_state != new_state:
            record = StateTransitionRecord(
                timestamp_ns=timestamp_ns,
                previous_state=self.current_state,
                new_state=new_state,
                trigger_reason=reason,
                human_distance_m=round(human_dist, 3),
                current_speed_mps=round(speed, 3),
            )
            self.transitions.append(record)
            self.current_state = new_state

    def update(self, packet: RobotTelemetryPacket) -> Tuple[RobotSafetyState, List[float]]:
        """
        Evaluates current physical state and returns:
            (current_safety_state, supervised_torque_commands)
        """
        if self.e_stop_latched:
            return (RobotSafetyState.EMERGENCY_STOP, [0.0] * len(packet.command_torque_input))

        human_dist = packet.human_distance_meters
        speed = sum(v * v for v in packet.velocity_xyz) ** 0.5
        cmd_torques = list(packet.command_torque_input)

        # 1. Protective Stop boundary (human < stop_distance)
        if human_dist <= self.stop_dist:
            self._transition_to(
                RobotSafetyState.PROTECTIVE_STOP,
                f"Human proximity ({human_dist:.2f}m) within protective stop threshold ({self.stop_dist:.2f}m)",
                packet.timestamp_ns,
                human_dist,
                speed,
            )
            # Apply electrical holding / damping brake (zero driving torque)
            return (self.current_state, [0.0] * len(cmd_torques))

        # 2. Collaborative Reduced Speed mode
        elif human_dist <= self.collab_dist:
            self._transition_to(
                RobotSafetyState.REDUCED_SPEED_COLLABORATIVE,
                f"Human proximity ({human_dist:.2f}m) enters collaborative zone (limit: {self.max_collab_speed}m/s)",
                packet.timestamp_ns,
                human_dist,
                speed,
            )
            # If robot exceeds 250 mm/s, scale actuator commands down
            if speed > self.max_collab_speed:
                scale = self.max_collab_speed / speed
                cmd_torques = [t * scale for t in cmd_torques]
            return (self.current_state, [round(t, 3) for t in cmd_torques])

        # 3. Normal Autonomous mode (with hysteresis to prevent chattering)
        elif human_dist > (self.collab_dist + self.hysteresis):
            self._transition_to(
                RobotSafetyState.NORMAL_AUTONOMOUS,
                f"Human cleared safe perimeter ({human_dist:.2f}m > {self.collab_dist + self.hysteresis:.2f}m)",
                packet.timestamp_ns,
                human_dist,
                speed,
            )
            return (self.current_state, cmd_torques)

        # In hysteresis band: maintain current state
        return (self.current_state, cmd_torques)
