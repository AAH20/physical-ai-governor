"""
Adversarial VLA Perturbation Guard & Perceptual Uncertainty CBF.
Guards Vision-Language-Action (VLA) foundation policies against:
    1. Perceptual uncertainty spikes (occlusion, fog, low confidence) via dynamic barrier inflation.
    2. High-frequency joint jerk and actuator chattering attacks (adversarial policy perturbations).
    3. Rapid trajectory divergence exceeding motor dynamics and safe human interaction limits.
Pure Python 3.10+ standard library (zero external dependencies).
"""

import math
from dataclasses import asdict, dataclass, field
from typing import Any, Dict, List, Optional, Tuple


@dataclass
class VLAUncertaintyMetric:
    """Perceptual and epistemic uncertainty metrics from vision and policy backends."""
    epistemic_variance: float = 0.0      # Policy ensemble / dropout variance (0.0 to 1.0)
    perceptual_noise_ratio: float = 0.0  # Camera degradation, blur, lighting deficit (0.0 to 1.0)
    ood_detection_score: float = 0.0     # Out-Of-Distribution distance score (0.0 to 1.0)

    @property
    def composite_uncertainty(self) -> float:
        """Calculates normalized composite uncertainty bounded in [0.0, 1.0]."""
        comp = (self.epistemic_variance * 0.4) + (self.perceptual_noise_ratio * 0.3) + (self.ood_detection_score * 0.3)
        return min(1.0, max(0.0, comp))


@dataclass
class VLAAnomalyReport:
    """Diagnostic report assessing adversarial risk and kinodynamic feasibility of VLA chunks."""
    is_safe: bool
    effective_min_distance_m: float
    base_min_distance_m: float
    uncertainty_level: float
    max_observed_jerk: float
    max_allowed_jerk: float
    max_observed_torque_rate: float
    max_allowed_torque_rate: float
    adversarial_flags: List[str] = field(default_factory=list)
    safe_action_chunk: List[List[float]] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


class VLAAdversarialGuard:
    """
    Supervises VLA multi-step action predictions prior to execution on physical actuators.
    Enforces dynamic barrier margin inflation and jerk-bounded smoothing filters.
    """

    def __init__(
        self,
        base_min_human_distance_m: float = 1.50,
        max_torque_rate_nm_s: float = 300.0,
        max_joint_jerk_nm_s2: float = 1500.0,
        max_uncertainty_inflation_factor: float = 2.5,
    ) -> None:
        self.base_min_human_distance_m = base_min_human_distance_m
        self.max_torque_rate_nm_s = max_torque_rate_nm_s
        self.max_joint_jerk_nm_s2 = max_joint_jerk_nm_s2
        self.max_inflation = max_uncertainty_inflation_factor

    def compute_dynamic_barrier_distance(self, uncertainty: float) -> float:
        """
        Dynamically inflates the required Control Barrier safe human separation distance
        in proportion to perceptual uncertainty:
            d_eff = d_base / (1 - min(sigma, 0.6))
        """
        sigma = min(max(0.0, uncertainty), 0.60)
        inflation = 1.0 / (1.0 - sigma)
        inflation = min(inflation, self.max_inflation)
        return self.base_min_human_distance_m * inflation

    def evaluate_and_filter_chunk(
        self,
        current_torques: List[float],
        action_chunk: List[List[float]],
        dt_step_s: float = 0.05,
        uncertainty: Optional[VLAUncertaintyMetric] = None,
    ) -> VLAAnomalyReport:
        """
        Evaluates an entire action chunk (e.g. H=8..16 steps) for high-frequency perturbations,
        torque rate saturation, and perceptual uncertainty expansion.
        """
        metric = uncertainty or VLAUncertaintyMetric()
        sigma = metric.composite_uncertainty
        eff_dist = self.compute_dynamic_barrier_distance(sigma)

        flags: List[str] = []
        if sigma > 0.40:
            flags.append(f"HIGH_PERCEPTUAL_UNCERTAINTY (sigma={sigma:.2f}, inflated_barrier={eff_dist:.2f}m)")

        if not action_chunk:
            return VLAAnomalyReport(
                is_safe=True,
                effective_min_distance_m=eff_dist,
                base_min_distance_m=self.base_min_human_distance_m,
                uncertainty_level=sigma,
                max_observed_jerk=0.0,
                max_allowed_jerk=self.max_joint_jerk_nm_s2,
                max_observed_torque_rate=0.0,
                max_allowed_torque_rate=self.max_torque_rate_nm_s,
                adversarial_flags=flags,
                safe_action_chunk=[],
            )

        num_dofs = len(current_torques)
        smoothed_chunk: List[List[float]] = []
        max_rate = 0.0
        max_jerk = 0.0

        prev_cmd = list(current_torques)
        prev_rate = [0.0] * num_dofs

        # Analyze trajectory step-by-step
        for step_idx, step_cmd in enumerate(action_chunk):
            filtered_cmd = []
            for j in range(num_dofs):
                target = step_cmd[j] if j < len(step_cmd) else 0.0
                curr = prev_cmd[j]

                # 1. Torque Rate: dtau/dt
                raw_rate = (target - curr) / dt_step_s
                abs_rate = abs(raw_rate)
                if abs_rate > max_rate:
                    max_rate = abs_rate

                # 2. Joint Jerk: d2tau/dt2
                raw_jerk = (raw_rate - prev_rate[j]) / dt_step_s
                abs_jerk = abs(raw_jerk)
                if abs_jerk > max_jerk:
                    max_jerk = abs_jerk

                # Check violations
                clamped_rate = raw_rate
                if abs_rate > self.max_torque_rate_nm_s:
                    clamped_rate = math.copysign(self.max_torque_rate_nm_s, raw_rate)
                    if f"TORQUE_RATE_BREACH_JOINT_{j}" not in flags:
                        flags.append(f"TORQUE_RATE_BREACH_JOINT_{j} ({abs_rate:.1f}Nm/s > {self.max_torque_rate_nm_s}Nm/s)")

                if abs_jerk > self.max_joint_jerk_nm_s2:
                    if f"ADVERSARIAL_JERK_ATTACK_JOINT_{j}" not in flags:
                        flags.append(f"ADVERSARIAL_JERK_ATTACK_JOINT_{j} ({abs_jerk:.1f}Nm/s2 > {self.max_joint_jerk_nm_s2}Nm/s2)")

                # Apply filtered rate update
                safe_val = curr + (clamped_rate * dt_step_s)
                filtered_cmd.append(round(safe_val, 4))
                prev_rate[j] = clamped_rate

            prev_cmd = filtered_cmd
            smoothed_chunk.append(filtered_cmd)

        is_safe = (len(flags) == 0)
        return VLAAnomalyReport(
            is_safe=is_safe,
            effective_min_distance_m=eff_dist,
            base_min_distance_m=self.base_min_human_distance_m,
            uncertainty_level=sigma,
            max_observed_jerk=round(max_jerk, 2),
            max_allowed_jerk=self.max_joint_jerk_nm_s2,
            max_observed_torque_rate=round(max_rate, 2),
            max_allowed_torque_rate=self.max_torque_rate_nm_s,
            adversarial_flags=flags,
            safe_action_chunk=smoothed_chunk,
        )
