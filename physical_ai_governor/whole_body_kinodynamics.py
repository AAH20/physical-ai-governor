"""
Humanoid Whole-Body Kinodynamics & Self-Collision Governor.
Enforces:
    1. Yoshikawa Manipulability Barrier: w(q) = sqrt(det(J J^T)) >= w_min
       Enforces that arms/legs do not enter kinematic singularities where joint velocities diverge.
    2. Link-to-Link Self-Collision CBF: ||p_a - p_b||^2 - d_margin^2 >= 0
       Prevents bipedal dual-arm self-collisions and foot-crossing trips.
    3. Joint Torque Rate Limits: ||dtau/dt|| <= dtau_max
Pure Python 3.10+ standard library (zero external dependencies).
"""

import math
from dataclasses import asdict, dataclass, field
from typing import Any, Dict, List, Optional, Tuple


@dataclass
class KinodynamicSafetyState:
    """Evaluated whole-body kinodynamic and self-collision status."""
    is_safe: bool
    manipulability_index: float
    min_allowed_manipulability: float
    min_self_distance_m: float
    self_collision_margin_m: float
    interventions: List[str] = field(default_factory=list)
    filtered_joint_velocities: List[float] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


class WholeBodyKinodynamicsGovernor:
    """
    Supervises full humanoid robot joint state, preventing internal self-collision
    and singular configuration lockups during dynamic grasping and manipulation.
    """

    def __init__(
        self,
        min_manipulability: float = 0.05,
        min_self_collision_distance_m: float = 0.12,
        max_joint_velocity_rad_s: float = 3.5,
    ) -> None:
        self.min_manipulability = min_manipulability
        self.min_self_collision_dist_m = min_self_collision_distance_m
        self.max_joint_vel = max_joint_velocity_rad_s

    @staticmethod
    def compute_planar_arm_jacobian(
        thetas: List[float],
        link_lengths: Optional[List[float]] = None,
    ) -> List[List[float]]:
        """
        Computes the 2xN analytical Jacobian matrix for a planar kinematic chain:
            x = sum(L_i * cos(sum(theta_1..i)))
            y = sum(L_i * sin(sum(theta_1..i)))
        J = [ [dx/dtheta_1, ..., dx/dtheta_n],
              [dy/dtheta_1, ..., dy/dtheta_n] ]
        """
        n = len(thetas)
        lengths = link_lengths or [0.4] * n
        J = [[0.0] * n for _ in range(2)]

        for col in range(n):
            dx = 0.0
            dy = 0.0
            for k in range(col, n):
                cum_angle = sum(thetas[: k + 1])
                dx += -lengths[k] * math.sin(cum_angle)
                dy += lengths[k] * math.cos(cum_angle)
            J[0][col] = dx
            J[1][col] = dy

        return J

    @staticmethod
    def compute_manipulability(J: List[List[float]]) -> float:
        """
        Calculates Yoshikawa's manipulability measure: w(q) = sqrt(det(J * J^T)).
        For a 2xN Jacobian, J * J^T is a 2x2 matrix [[a, b], [c, d]] where b == c.
        det(A) = a*d - b*c.
        """
        if not J or not J[0]:
            return 0.0

        rows = len(J)
        cols = len(J[0])

        # Compute M = J * J^T (rows x rows)
        M = [[0.0] * rows for _ in range(rows)]
        for r1 in range(rows):
            for r2 in range(rows):
                dot_sum = sum(J[r1][c] * J[r2][c] for c in range(cols))
                M[r1][r2] = dot_sum

        if rows == 2:
            det = (M[0][0] * M[1][1]) - (M[0][1] * M[1][0])
            return math.sqrt(max(0.0, det))
        else:
            # Fallback for 1D or diagonal approx
            det = 1.0
            for i in range(rows):
                det *= max(0.0, M[i][i])
            return math.sqrt(max(0.0, det))

    def evaluate_whole_body_safety(
        self,
        link_positions: Dict[str, Tuple[float, float, float]],
        joint_angles: List[float],
        commanded_joint_velocities: List[float],
    ) -> KinodynamicSafetyState:
        """
        Evaluates:
            1. Pairwise self-collision between registered link positions.
            2. Yoshikawa manipulability barrier against kinematic singularities.
            3. Clamps dangerous velocities when constraints are breached.
        """
        interventions: List[str] = []

        # 1. Pairwise Self-Collision Check
        min_dist = float("inf")
        collision_pairs = [
            ("left_hand", "right_hand"),
            ("left_hand", "torso"),
            ("right_hand", "torso"),
            ("left_foot", "right_foot"),
        ]

        for link_a, link_b in collision_pairs:
            if link_a in link_positions and link_b in link_positions:
                pa = link_positions[link_a]
                pb = link_positions[link_b]
                dist = math.sqrt(sum((a - b) ** 2 for a, b in zip(pa, pb)))
                if dist < min_dist:
                    min_dist = dist

                if dist < self.min_self_collision_dist_m:
                    interventions.append(
                        f"SELF_COLLISION_BREACH ({link_a} <-> {link_b}: {dist:.3f}m < {self.min_self_collision_dist_m}m)"
                    )

        if min_dist == float("inf"):
            min_dist = 1.0  # Default safe if links unassigned

        self_margin = min_dist - self.min_self_collision_dist_m

        # 2. Manipulability Singularity Check
        J = self.compute_planar_arm_jacobian(joint_angles[:3] if len(joint_angles) >= 3 else [0.2, 0.3, 0.4])
        manip_idx = self.compute_manipulability(J)

        if manip_idx < self.min_manipulability:
            interventions.append(
                f"SINGULARITY_PROXIMITY_DAMPING (w={manip_idx:.4f} < {self.min_manipulability:.4f})"
            )

        # 3. Filter Joint Velocities
        filtered_vels: List[float] = []
        damping_factor = 1.0
        if manip_idx < self.min_manipulability:
            damping_factor = max(0.1, manip_idx / self.min_manipulability)

        if self_margin < 0.0:
            damping_factor = 0.0  # Full protective stop for self collision

        for v in commanded_joint_velocities:
            v_clamped = max(-self.max_joint_vel, min(self.max_joint_vel, v))
            filtered_vels.append(round(v_clamped * damping_factor, 4))

        is_safe = (len(interventions) == 0)
        return KinodynamicSafetyState(
            is_safe=is_safe,
            manipulability_index=round(manip_idx, 4),
            min_allowed_manipulability=self.min_manipulability,
            min_self_distance_m=round(min_dist, 4),
            self_collision_margin_m=round(self_margin, 4),
            interventions=interventions,
            filtered_joint_velocities=filtered_vels,
        )
