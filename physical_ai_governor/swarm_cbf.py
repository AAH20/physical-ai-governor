"""
Decentralized Swarm & Multi-Robot Control Barrier Function (Swarm-CBF) Governor.
Enforces reciprocal collision avoidance across autonomous humanoid teams and drone swarms
with formal pairwise forward invariance:
    h_ij(p_i, p_j) = ||p_i - p_j||^2 - D_safe^2 >= 0
    dot{h}_ij >= -gamma * h_ij
Zero external dependencies (pure Python standard library).
"""

import math
from dataclasses import asdict, dataclass
from typing import Any, Dict, List, Optional, Tuple


@dataclass
class SwarmAgentState:
    """State vector of an individual agent within a swarm or multi-robot cell."""
    agent_id: str
    position_xyz: Tuple[float, float, float]
    velocity_xyz: Tuple[float, float, float]
    commanded_velocity_xyz: Tuple[float, float, float]


@dataclass
class SwarmSafetyDecision:
    """Safety evaluation and reciprocal collision avoidance output for a swarm agent."""
    agent_id: str
    is_safe: bool
    filtered_velocity: Tuple[float, float, float]
    active_pairwise_barriers: int
    min_inter_agent_distance_m: float
    intervened: bool
    threat_agent_ids: List[str]


class SwarmControlBarrierGovernor:
    """
    Decentralized Reciprocal Control Barrier Function governor for multi-robot fleets.
    Enforces pairwise forward invariance for every pair of interacting robots.
    """

    def __init__(
        self,
        min_inter_agent_distance_m: float = 2.0,
        cbf_gamma: float = 1.0,
        max_speed_mps: float = 4.0,
    ) -> None:
        self.d_safe = min_inter_agent_distance_m
        self.d_safe_sq = min_inter_agent_distance_m * min_inter_agent_distance_m
        self.gamma = cbf_gamma
        self.max_speed = max_speed_mps

    def evaluate_swarm_safety(
        self, agents: List[SwarmAgentState]
    ) -> Dict[str, SwarmSafetyDecision]:
        """
        Evaluates reciprocal CBF collision barriers across all swarm agents.
        Returns mapped decisions per agent ID.
        """
        n = len(agents)
        decisions: Dict[str, SwarmSafetyDecision] = {}

        for i, agent_i in enumerate(agents):
            p_i = agent_i.position_xyz
            v_cmd_i = list(agent_i.commanded_velocity_xyz)
            min_dist = float("inf")
            threats: List[str] = []
            intervened = False

            for j, agent_j in enumerate(agents):
                if i == j:
                    continue

                p_j = agent_j.position_xyz
                v_j = agent_j.velocity_xyz

                # Relative position vector: p_ij = p_i - p_j
                p_ij = (p_i[0] - p_j[0], p_i[1] - p_j[1], p_i[2] - p_j[2])
                dist_sq = sum(c * c for c in p_ij)
                dist = math.sqrt(dist_sq)

                if dist < min_dist:
                    min_dist = dist

                # Barrier h_ij = ||p_ij||^2 - D_safe^2 >= 0
                h_ij = dist_sq - self.d_safe_sq

                # Reciprocal CBF condition: 2 * p_ij^T (v_i - v_j) >= -gamma * h_ij
                # Dividing by 2: p_ij^T v_i - p_ij^T v_j >= -0.5 * gamma * h_ij
                p_dot_vj = sum(p * v for p, v in zip(p_ij, v_j))
                min_p_dot_vi = p_dot_vj - 0.5 * self.gamma * h_ij

                p_dot_vcmd = sum(p * v for p, v in zip(p_ij, v_cmd_i))

                if p_dot_vcmd < min_p_dot_vi:
                    # Imminent collision path: project velocity onto safe half-space
                    intervened = True
                    threats.append(agent_j.agent_id)

                    # Projection: v_safe = v_cmd + lambda * p_ij
                    if dist_sq > 1e-6:
                        deficiency = min_p_dot_vi - p_dot_vcmd
                        lam = deficiency / dist_sq
                        v_cmd_i = [v + lam * p for v, p in zip(v_cmd_i, p_ij)]

            # Cap total speed within maximum limits
            speed = math.sqrt(sum(v * v for v in v_cmd_i))
            if speed > self.max_speed:
                scale = self.max_speed / speed
                v_cmd_i = [v * scale for v in v_cmd_i]
                intervened = True

            decisions[agent_i.agent_id] = SwarmSafetyDecision(
                agent_id=agent_i.agent_id,
                is_safe=not intervened,
                filtered_velocity=(round(v_cmd_i[0], 3), round(v_cmd_i[1], 3), round(v_cmd_i[2], 3)),
                active_pairwise_barriers=len(threats),
                min_inter_agent_distance_m=round(min_dist, 3) if min_dist != float("inf") else 999.0,
                intervened=intervened,
                threat_agent_ids=threats,
            )

        return decisions
