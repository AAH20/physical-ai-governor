"""
Control Barrier Function (CBF) Safety Filters & Humanoid Governors.
Enforces continuous mathematical safety barriers over robot actuator commands,
monitoring human proximity boundaries, torque limits, and dynamic deceleration constraints.
Zero external dependencies (pure Python standard library).
"""

import math
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple

from .qp_solver import ActiveSetQPSolver
from .telemetry_ingest import RobotTelemetryPacket


def _check_finite(val: Any) -> bool:
    """Validates that a scalar value is a finite number (not NaN or Inf)."""
    return isinstance(val, (int, float)) and not math.isnan(val) and not math.isinf(val)


@dataclass
class SafetyDecision:
    """Outcome of a real-time Control Barrier Function evaluation."""
    is_safe: bool
    original_command: List[float]
    filtered_command: List[float]
    cbf_margin: float
    intervention_triggered: bool
    violation_reason: Optional[str]
    decision_status: str = "SAFE_NOMINAL"


@dataclass
class HumanoidStabilityState:
    """Bipedal humanoid physical stability metrics."""
    zmp_xy: Tuple[float, float]
    zmp_inside_support: bool
    friction_cone_satisfied: bool
    self_collision_safe: bool
    composite_stable: bool
    stability_margin: float
    violations: List[str] = field(default_factory=list)


class ControlBarrierFilter:
    """
    Control Barrier Function (CBF) safety governor.
    Evaluates:
        h(x) >= 0  (Safety set C)
        dh/dt >= -alpha * h(x)
    If the commanded actuator vector violates the barrier, clamps to the nearest safe projection.
    Note: The zero-command fallback ([0.0] * n) is a simulated fail-safe fallback intended
    for software-in-the-loop (SIL) testing; physical robots require hold-position trajectory
    or mechanical brake engagement.
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
        n = len(original)

        # Validate finite inputs (guard against NaN / Inf)
        if (
            not all(_check_finite(x) for x in original)
            or not _check_finite(packet.human_distance_meters)
            or not all(_check_finite(x) for x in packet.velocity_xyz)
            or not all(_check_finite(x) for x in packet.position_xyz)
            or (packet.human_relative_position_xyz and not all(_check_finite(x) for x in packet.human_relative_position_xyz))
            or (packet.human_velocity_xyz and not all(_check_finite(x) for x in packet.human_velocity_xyz))
        ):
            return SafetyDecision(
                is_safe=False,
                original_command=original,
                filtered_command=[0.0] * n,
                cbf_margin=-1.0,
                intervention_triggered=True,
                violation_reason="INVALID_INPUT: Non-finite values (NaN/Inf) detected in telemetry packet. Engaged fail-safe protective stop.",
                decision_status="INVALID_INPUT",
            )

        # Cross-validate distance measurements if relative position vector is provided
        effective_human_distance = packet.human_distance_meters
        if packet.human_relative_position_xyz is not None:
            r_vec = packet.human_relative_position_xyz
            d_vec = math.sqrt(sum(x * x for x in r_vec))
            discrepancy = abs(packet.human_distance_meters - d_vec)
            allowed_tolerance = max(0.50, 0.25 * d_vec)
            if discrepancy > allowed_tolerance:
                return SafetyDecision(
                    is_safe=False,
                    original_command=original,
                    filtered_command=[0.0] * n,
                    cbf_margin=-1.0,
                    intervention_triggered=True,
                    violation_reason=(
                        f"SENSOR_DISCREPANCY: Disagreement between scalar human_distance_meters ({packet.human_distance_meters:.2f}m) "
                        f"and norm(human_relative_position_xyz) ({d_vec:.2f}m) exceeds tolerance ({allowed_tolerance:.2f}m). "
                        "Engaged fail-safe protective stop."
                    ),
                    decision_status="INVALID_INPUT",
                )
            # Conservatively select minimum distance
            effective_human_distance = min(packet.human_distance_meters, d_vec)

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
        prox_margin = effective_human_distance - self.min_human_distance_m
        if prox_margin < 0:
            intervened = True
            reasons.append(
                f"Human proximity ({effective_human_distance:.2f}m) breaches safe barrier ({self.min_human_distance_m:.2f}m)"
            )
            # Apply emergency proportional damping to reduce actuator authority
            damping_factor = max(0.0, effective_human_distance / self.min_human_distance_m)
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
            decision_status="SAFE_FILTERED" if intervened else "SAFE_NOMINAL",
        )


class QPSafetyFilter:
    """
    Formal Optimization-based Control Barrier Function (QP-CBF) Safety Filter.
    Solves strictly convex Quadratic Program:
        minimize    0.5 * ||u - u_nom||^2
        subject to  A_cbf * u <= b_cbf
                    -tau_max <= u_i <= tau_max
    Calculates minimal-deviation intervention from AI nominal actions under forward invariance constraints.
    Engages a fail-safe protective stop ([0.0] * n) upon infeasibility or solver failure.
    Note: The zero-command fallback ([0.0] * n) is a simulated fail-safe fallback intended
    for software-in-the-loop (SIL) testing; physical robots require hold-position trajectory
    or mechanical brake engagement.
    """

    def __init__(
        self,
        min_human_distance_m: float = 1.50,
        max_joint_torque_nm: float = 150.0,
        max_velocity_mps: float = 4.0,
        cbf_gamma: float = 1.5,
    ) -> None:
        self.min_human_distance_m = min_human_distance_m
        self.max_joint_torque_nm = max_joint_torque_nm
        self.max_velocity_mps = max_velocity_mps
        self.cbf_gamma = cbf_gamma
        self.solver = ActiveSetQPSolver(max_iterations=50)

    def evaluate_safety_qp(
        self,
        packet: RobotTelemetryPacket,
        control_matrix_g: Optional[List[List[float]]] = None,
    ) -> SafetyDecision:
        """
        Solves minimal-deviation QP CBF filter for commanded torques.
        control_matrix_g maps actuator commands to position/velocity dynamics: x_dot = f(x) + g(x) * u.
        """
        u_nom = packet.command_torque_input
        n = len(u_nom)
        if n == 0:
            return SafetyDecision(
                is_safe=True,
                original_command=[],
                filtered_command=[],
                cbf_margin=1.0,
                intervention_triggered=False,
                violation_reason=None,
                decision_status="SAFE_NOMINAL",
            )

        # Validate finite inputs (guard against NaN / Inf)
        if (
            not all(_check_finite(x) for x in u_nom)
            or not _check_finite(packet.human_distance_meters)
            or not all(_check_finite(x) for x in packet.velocity_xyz)
            or not all(_check_finite(x) for x in packet.position_xyz)
            or (packet.human_relative_position_xyz and not all(_check_finite(x) for x in packet.human_relative_position_xyz))
            or (packet.human_velocity_xyz and not all(_check_finite(x) for x in packet.human_velocity_xyz))
        ):
            return SafetyDecision(
                is_safe=False,
                original_command=u_nom,
                filtered_command=[0.0] * n,
                cbf_margin=-1.0,
                intervention_triggered=True,
                violation_reason="INVALID_INPUT: Non-finite values (NaN/Inf) detected in telemetry packet. Engaged fail-safe protective stop.",
                decision_status="INVALID_INPUT",
            )

        # Cross-validate distance measurements if relative position vector is provided
        effective_human_distance = packet.human_distance_meters
        if packet.human_relative_position_xyz is not None:
            r_vec = packet.human_relative_position_xyz
            d_vec = math.sqrt(sum(x * x for x in r_vec))
            discrepancy = abs(packet.human_distance_meters - d_vec)
            allowed_tolerance = max(0.50, 0.25 * d_vec)
            if discrepancy > allowed_tolerance:
                return SafetyDecision(
                    is_safe=False,
                    original_command=u_nom,
                    filtered_command=[0.0] * n,
                    cbf_margin=-1.0,
                    intervention_triggered=True,
                    violation_reason=(
                        f"SENSOR_DISCREPANCY: Disagreement between scalar human_distance_meters ({packet.human_distance_meters:.2f}m) "
                        f"and norm(human_relative_position_xyz) ({d_vec:.2f}m) exceeds tolerance ({allowed_tolerance:.2f}m). "
                        "Engaged fail-safe protective stop."
                    ),
                    decision_status="INVALID_INPUT",
                )
            effective_human_distance = min(packet.human_distance_meters, d_vec)

        # Objective: 0.5 * u^T I u - u_nom^T u  <=> min 0.5 * ||u - u_nom||^2
        P = [[1.0 if i == j else 0.0 for j in range(n)] for i in range(n)]
        q = [-float(val) for val in u_nom]

        u_min = [-self.max_joint_torque_nm] * n
        u_max = [self.max_joint_torque_nm] * n

        A_cbf: List[List[float]] = []
        b_cbf: List[float] = []
        reasons: List[str] = []

        # 1. Proximity Barrier: h_prox = d - d_safe >= 0
        h_prox = effective_human_distance - self.min_human_distance_m
        vel_mag = math.sqrt(sum(v * v for v in packet.velocity_xyz))

        # Directional relative Lie derivative L_f h(x) = \nabla h(x) \cdot f(x)
        # When relative human position is provided (r_h = p_human - p_robot):
        # dh/dt = d(||r_h||)/dt = - r_hat . (v_robot - v_human)
        if packet.human_relative_position_xyz is not None:
            r_rel = packet.human_relative_position_xyz
            r_norm = math.sqrt(sum(x * x for x in r_rel))
            if r_norm > 1e-3:
                r_hat = [x / r_norm for x in r_rel]
                v_h = packet.human_velocity_xyz if packet.human_velocity_xyz is not None else (0.0, 0.0, 0.0)
                v_rel = [vr - vh for vr, vh in zip(packet.velocity_xyz, v_h)]
                drift_lf = -sum(rh * vr for rh, vr in zip(r_hat, v_rel))
            else:
                drift_lf = -vel_mag
        else:
            # Conservative worst-case approach bound when relative bearing is unavailable
            drift_lf = -vel_mag

        # Wire control_matrix_g into Lie derivative CBF constraints:
        # L_g h(x) * u >= - L_f h(x) - gamma * h(x)  <=>  - L_g h(x) * u <= L_f h(x) + gamma * h(x)
        if control_matrix_g:
            for g_idx, g_row in enumerate(control_matrix_g):
                if len(g_row) == n:
                    A_cbf.append([-float(val) for val in g_row])
                    # L_f h(x) directional drift term + gamma * h(x)
                    b_val = drift_lf + self.cbf_gamma * max(0.0, h_prox)
                    b_cbf.append(b_val)
                    reasons.append(f"QP CBF control_matrix_g[{g_idx}] Constraint Active")

        # dh/dt = -v_rel >= -gamma * h(x)  => v_rel <= gamma * h(x)
        if h_prox < 0.5 and not control_matrix_g:
            # Fallback coupled constraint bounding total deceleration authority if g not provided
            # sum(u_i) <= max_allowable when close
            max_forward_effort = max(0.0, (h_prox / 0.5)) * self.max_joint_torque_nm * n
            row = [1.0] * n
            A_cbf.append(row)
            b_cbf.append(max_forward_effort)
            reasons.append(f"QP CBF Proximity Constraint Active (h={h_prox:.2f}m)")

        # 2. Velocity Barrier
        if vel_mag > self.max_velocity_mps * 0.9:
            scale_bound = (self.max_velocity_mps / max(1e-3, vel_mag)) * self.max_joint_torque_nm
            row_vel = [1.0 if t > 0 else -1.0 for t in u_nom]
            A_cbf.append(row_vel)
            b_cbf.append(scale_bound)
            reasons.append(f"QP CBF Velocity Constraint Active (vel={vel_mag:.2f}m/s)")

        sol = self.solver.solve(
            P=P,
            q=q,
            A=A_cbf if A_cbf else None,
            b=b_cbf if b_cbf else None,
            u_min=u_min,
            u_max=u_max,
        )

        # Inspect solver feasibility and convergence
        if not sol.converged or not sol.constraints_satisfied or sol.max_constraint_violation > 1e-3:
            fail_status = "INFEASIBLE" if not sol.constraints_satisfied else "SOLVER_FAILURE"
            fail_reason = (
                f"QP CBF {fail_status} (max_violation={sol.max_constraint_violation:.4f}); "
                "safety constraints cannot be satisfied simultaneously. "
                "Engaged fail-safe protective stop (zero command)."
            )
            return SafetyDecision(
                is_safe=False,
                original_command=u_nom,
                filtered_command=[0.0] * n,
                cbf_margin=-sol.max_constraint_violation,
                intervention_triggered=True,
                violation_reason=fail_reason,
                decision_status=fail_status,
            )

        filtered = sol.u
        is_intervened = any(abs(f - orig) > 1e-3 for f, orig in zip(filtered, u_nom))
        composite_margin = min(
            self.max_joint_torque_nm - max(abs(t) for t in filtered),
            h_prox,
        )

        return SafetyDecision(
            is_safe=not is_intervened,
            original_command=u_nom,
            filtered_command=[round(x, 3) for x in filtered],
            cbf_margin=round(composite_margin, 3),
            intervention_triggered=is_intervened,
            violation_reason="; ".join(reasons) if is_intervened else None,
            decision_status="SAFE_FILTERED" if is_intervened else "SAFE_NOMINAL",
        )


class HighOrderControlBarrierFilter:
    """
    High-Order Control Barrier Function (HOCBF) for relative-degree r=2 systems.
    Protects physical kinematic chains where control input directly drives acceleration/torque,
    requiring smooth second-order barrier satisfaction:
        psi_0(x) = h(x)
        psi_1(x) = dot{psi}_0(x) + alpha_1(psi_0(x))
        psi_2(x, u) = dot{psi}_1(x, u) + alpha_2(psi_1(x)) >= 0
    """

    def __init__(
        self,
        safe_distance_m: float = 1.50,
        max_deceleration_mps2: float = 5.0,
        alpha_1: float = 1.0,
        alpha_2: float = 1.5,
    ) -> None:
        self.safe_distance_m = safe_distance_m
        self.max_decel = max_deceleration_mps2
        self.alpha_1 = alpha_1
        self.alpha_2 = alpha_2

    def evaluate_hocbf(
        self,
        relative_distance: float,
        approach_velocity: float,
        commanded_acceleration: float,
    ) -> Tuple[bool, float, float]:
        """
        Evaluates second-order safety barrier.
        Returns: (is_safe, psi_1_margin, filtered_acceleration)
        """
        psi_0 = relative_distance - self.safe_distance_m
        psi_1 = approach_velocity + self.alpha_1 * psi_0

        # Enforce dot{psi_1} + alpha_2 * psi_1 >= 0
        # dot{psi_1} = commanded_acceleration + alpha_1 * approach_velocity
        # => commanded_acceleration >= -alpha_1 * approach_velocity - alpha_2 * psi_1
        min_safe_accel = -self.alpha_1 * approach_velocity - self.alpha_2 * psi_1

        is_safe = commanded_acceleration >= min_safe_accel
        filtered_accel = commanded_acceleration

        if not is_safe:
            filtered_accel = max(min_safe_accel, -self.max_decel)

        return (is_safe, round(psi_1, 3), round(filtered_accel, 3))


class HumanoidStabilityGovernor:
    """
    Bipedal Humanoid Dynamic Stability Governor.
    Monitors:
        1. Zero Moment Point (ZMP) within foot support polygon.
        2. Ground Reaction Force (GRF) Coulomb friction cone: sqrt(Fx^2 + Fy^2) <= mu * Fz.
        3. Multi-link self-collision clearance.
    """

    def __init__(
        self,
        support_polygon_x: Tuple[float, float] = (-0.15, 0.20),
        support_polygon_y: Tuple[float, float] = (-0.12, 0.12),
        friction_coefficient: float = 0.60,
        min_link_clearance_m: float = 0.08,
        gravity_mps2: float = 9.81,
    ) -> None:
        self.poly_x = support_polygon_x
        self.poly_y = support_polygon_y
        self.mu = friction_coefficient
        self.min_clearance = min_link_clearance_m
        self.g = gravity_mps2

    def compute_zmp(
        self,
        com_pos: Tuple[float, float, float],
        com_acc: Tuple[float, float, float],
    ) -> Tuple[float, float]:
        """
        Computes 2D Zero Moment Point using inverted pendulum cart-table model:
            x_zmp = x_com - (z_com / g) * x_acc
            y_zmp = y_com - (z_com / g) * y_acc
        """
        x_c, y_c, z_c = com_pos
        x_a, y_a, _ = com_acc
        z_eff = max(0.2, z_c)
        x_zmp = x_c - (z_eff / self.g) * x_a
        y_zmp = y_c - (z_eff / self.g) * y_a
        return (round(x_zmp, 4), round(y_zmp, 4))

    def evaluate_stability(
        self,
        com_pos: Tuple[float, float, float],
        com_acc: Tuple[float, float, float],
        ground_reaction_force_xyz: Tuple[float, float, float],
        inter_link_distance_m: float = 0.25,
    ) -> HumanoidStabilityState:
        """
        Full evaluation of humanoid physical balance and kinematic safety.
        """
        violations: List[str] = []
        zmp_x, zmp_y = self.compute_zmp(com_pos, com_acc)

        # 1. ZMP Support Polygon check
        zmp_ok = (
            self.poly_x[0] <= zmp_x <= self.poly_x[1]
            and self.poly_y[0] <= zmp_y <= self.poly_y[1]
        )
        if not zmp_ok:
            violations.append(
                f"ZMP ({zmp_x:.3f}, {zmp_y:.3f}) outside foot support polygon x:[{self.poly_x[0]}, {self.poly_x[1]}], y:[{self.poly_y[0]}, {self.poly_y[1]}]"
            )

        # 2. Friction Cone check: sqrt(Fx^2 + Fy^2) <= mu * Fz
        fx, fy, fz = ground_reaction_force_xyz
        tangential_force = math.hypot(fx, fy)
        normal_limit = max(0.0, fz * self.mu)
        friction_ok = (fz > 5.0) and (tangential_force <= normal_limit)
        if not friction_ok:
            violations.append(
                f"Friction cone violated: tangential force {tangential_force:.1f}N > normal capacity {normal_limit:.1f}N (Fz={fz:.1f}N)"
            )

        # 3. Multi-link self-collision clearance
        collision_ok = inter_link_distance_m >= self.min_clearance
        if not collision_ok:
            violations.append(
                f"Self-collision proximity ({inter_link_distance_m:.3f}m) below safety threshold ({self.min_clearance:.3f}m)"
            )

        is_stable = zmp_ok and friction_ok and collision_ok
        # Margin: distance from boundary of polygon
        margin_x = min(zmp_x - self.poly_x[0], self.poly_x[1] - zmp_x)
        margin_y = min(zmp_y - self.poly_y[0], self.poly_y[1] - zmp_y)
        stab_margin = round(min(margin_x, margin_y), 4)

        return HumanoidStabilityState(
            zmp_xy=(zmp_x, zmp_y),
            zmp_inside_support=zmp_ok,
            friction_cone_satisfied=friction_ok,
            self_collision_safe=collision_ok,
            composite_stable=is_stable,
            stability_margin=stab_margin,
            violations=violations,
        )
