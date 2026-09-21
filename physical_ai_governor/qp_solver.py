"""
Pure Python Active-Set Quadratic Programming (QP) Solver.
Zero external dependencies (pure standard library).
Solves strictly convex quadratic programs of the form:
    minimize    0.5 * u^T P u + q^T u
    subject to  A u <= b
                u_min <= u <= u_max
Used by the Control Barrier Function (CBF) safety filter for minimal-intervention
actuator correction.
"""

import math
from dataclasses import dataclass
from typing import List, Optional, Tuple


@dataclass
class QPSolution:
    """Outcome of an Active-Set Quadratic Program optimization."""
    u: List[float]
    converged: bool
    iterations: int
    objective_value: float
    active_indices: List[int]
    lagrange_multipliers: List[float]
    constraints_satisfied: bool = True
    max_constraint_violation: float = 0.0


def _mat_vec_mul(A: List[List[float]], x: List[float]) -> List[float]:
    return [sum(row[j] * x[j] for j in range(len(x))) for row in A]


def _dot(a: List[float], b: List[float]) -> float:
    return sum(x * y for x, y in zip(a, b))


def _solve_linear_system(A: List[List[float]], b: List[float]) -> Optional[List[float]]:
    """
    Solves A x = b using Gaussian elimination with partial pivoting.
    Returns None if matrix is singular.
    """
    n = len(A)
    if n == 0 or len(b) != n:
        return None

    # Create augmented matrix [A | b]
    aug = [list(A[i]) + [b[i]] for i in range(n)]

    for i in range(n):
        # Pivot selection
        max_row = i
        max_val = abs(aug[i][i])
        for r in range(i + 1, n):
            if abs(aug[r][i]) > max_val:
                max_val = abs(aug[r][i])
                max_row = r

        if max_val < 1e-12:
            return None  # Singular or rank-deficient

        if max_row != i:
            aug[i], aug[max_row] = aug[max_row], aug[i]

        pivot = aug[i][i]
        for c in range(i, n + 1):
            aug[i][c] /= pivot

        for r in range(n):
            if r != i:
                factor = aug[r][i]
                if abs(factor) > 1e-15:
                    for c in range(i, n + 1):
                        aug[r][c] -= factor * aug[i][c]

    return [aug[i][n] for i in range(n)]


class ActiveSetQPSolver:
    """
    Primal Active-Set Quadratic Programming Solver.
    Designed for fast, bounded-latency runtime safety filters (<1ms).
    """

    def __init__(self, max_iterations: int = 50, tolerance: float = 1e-7) -> None:
        self.max_iterations = max_iterations
        self.tol = tolerance

    def solve(
        self,
        P: List[List[float]],
        q: List[float],
        A: Optional[List[List[float]]] = None,
        b: Optional[List[float]] = None,
        u_min: Optional[List[float]] = None,
        u_max: Optional[List[float]] = None,
    ) -> QPSolution:
        """
        Solves:
            min 0.5 * u^T P u + q^T u
            s.t. A u <= b, u_min <= u <= u_max
        """
        n = len(q)
        if n == 0:
            return QPSolution(
                u=[],
                converged=False,
                iterations=0,
                objective_value=float("inf"),
                active_indices=[],
                lagrange_multipliers=[],
                constraints_satisfied=False,
                max_constraint_violation=float("inf"),
            )

        # Validate finite numerical values
        def _has_nonfinite(arr) -> bool:
            for item in arr:
                if isinstance(item, (list, tuple)):
                    if _has_nonfinite(item):
                        return True
                elif not isinstance(item, (int, float)) or math.isnan(item) or math.isinf(item):
                    return True
            return False

        if _has_nonfinite(P) or _has_nonfinite(q) or (A and _has_nonfinite(A)) or (b and _has_nonfinite(b)) or (u_min and _has_nonfinite(u_min)) or (u_max and _has_nonfinite(u_max)):
            return QPSolution(
                u=[0.0] * n,
                converged=False,
                iterations=0,
                objective_value=float("inf"),
                active_indices=[],
                lagrange_multipliers=[],
                constraints_satisfied=False,
                max_constraint_violation=float("inf"),
            )

        # Check for contradictory box bounds (u_min[i] > u_max[i])
        if u_min is not None and u_max is not None:
            for i in range(n):
                if u_min[i] > u_max[i] + self.tol:
                    # Infeasible: contradictory upper/lower bounds
                    return QPSolution(
                        u=[round((u_min[i] + u_max[i]) / 2.0, 6) for i in range(n)],
                        converged=False,
                        iterations=0,
                        objective_value=float("inf"),
                        active_indices=[],
                        lagrange_multipliers=[],
                        constraints_satisfied=False,
                        max_constraint_violation=round(u_min[i] - u_max[i], 6),
                    )

        A_all: List[List[float]] = []
        b_all: List[float] = []

        # 1. Incorporate general linear inequality constraints
        if A is not None and b is not None:
            for row, bound in zip(A, b):
                A_all.append(list(row))
                b_all.append(float(bound))

        # 2. Incorporate box constraints
        if u_max is not None:
            for i in range(n):
                row = [0.0] * n
                row[i] = 1.0
                A_all.append(row)
                b_all.append(float(u_max[i]))

        if u_min is not None:
            for i in range(n):
                row = [0.0] * n
                row[i] = -1.0
                A_all.append(row)
                b_all.append(-float(u_min[i]))

        m = len(A_all)

        # Initial point: unconstrained solution u = -P^{-1} q, clamped to bounds
        u_init = _solve_linear_system(P, [-val for val in q])
        if u_init is None:
            u_init = [0.0] * n

        # Find initial feasible point
        u = list(u_init)
        for i in range(n):
            if u_min is not None and u[i] < u_min[i]:
                u[i] = u_min[i]
            if u_max is not None and u[i] > u_max[i]:
                u[i] = u_max[i]

        # Active set: indices of constraints in A_all currently treated as equalities
        active_set: List[int] = []
        for j in range(m):
            slack = b_all[j] - _dot(A_all[j], u)
            if abs(slack) < self.tol:
                active_set.append(j)
            elif slack < -self.tol:
                # Slight violation: project point onto constraint
                norm_sq = _dot(A_all[j], A_all[j])
                if norm_sq > 1e-12:
                    step = slack / norm_sq
                    for i in range(n):
                        u[i] += step * A_all[j][i]
                active_set.append(j)

        iterations = 0
        lagrange_mults: List[float] = [0.0] * m

        while iterations < self.max_iterations:
            iterations += 1
            k = len(active_set)

            # Form KKT matrix for the active subspace:
            # [ P       A_act^T ] [  p  ] = [ -g ]
            # [ A_act      0    ] [ lam ]   [  0 ]
            g = [sum(P[i][j] * u[j] for j in range(n)) + q[i] for i in range(n)]

            kkt_dim = n + k
            KKT = [[0.0] * kkt_dim for _ in range(kkt_dim)]
            rhs = [-g[i] for i in range(n)] + [0.0] * k

            for i in range(n):
                for j in range(n):
                    KKT[i][j] = P[i][j]

            for row_idx, constr_idx in enumerate(active_set):
                for j in range(n):
                    val = A_all[constr_idx][j]
                    KKT[n + row_idx][j] = val
                    KKT[j][n + row_idx] = val

            sol = _solve_linear_system(KKT, rhs)

            if sol is None:
                # If active set KKT is singular, drop a redundant constraint
                if active_set:
                    active_set.pop()
                    continue
                else:
                    break

            p = sol[:n]
            lambdas = sol[n:]

            p_norm = sum(x * x for x in p) ** 0.5

            if p_norm < self.tol:
                # Stationary point on current active set. Check multipliers.
                min_lam = 0.0
                drop_idx = -1
                for idx, lam in enumerate(lambdas):
                    if lam < min_lam - self.tol:
                        min_lam = lam
                        drop_idx = idx

                if drop_idx == -1:
                    # All active multipliers >= 0, optimal solution found!
                    for r_idx, c_idx in enumerate(active_set):
                        lagrange_mults[c_idx] = lambdas[r_idx]
                    break
                else:
                    # Drop constraint with negative multiplier
                    active_set.pop(drop_idx)
            else:
                # Step along p: find maximum step size alpha in [0, 1] without violating inactive constraints
                alpha = 1.0
                blocking_constraint = -1

                for j in range(m):
                    if j not in active_set:
                        a_dot_p = _dot(A_all[j], p)
                        if a_dot_p > self.tol:
                            slack = b_all[j] - _dot(A_all[j], u)
                            dist = max(0.0, slack) / a_dot_p
                            if dist < alpha:
                                alpha = dist
                                blocking_constraint = j

                for i in range(n):
                    u[i] += alpha * p[i]

                if blocking_constraint != -1 and alpha < 1.0 - self.tol:
                    active_set.append(blocking_constraint)

        # Verify constraint residuals over all constraints
        max_violation = 0.0
        for j in range(m):
            viol = _dot(A_all[j], u) - b_all[j]
            if viol > max_violation:
                max_violation = viol

        constraints_satisfied = (max_violation <= self.tol * 10.0)
        converged = (iterations < self.max_iterations) and constraints_satisfied

        obj = 0.5 * sum(u[i] * sum(P[i][j] * u[j] for j in range(n)) for i in range(n)) + _dot(q, u)

        return QPSolution(
            u=[round(x, 6) for x in u],
            converged=converged,
            iterations=iterations,
            objective_value=round(obj, 6) if not math.isnan(obj) else float("inf"),
            active_indices=sorted(active_set),
            lagrange_multipliers=[round(x, 6) for x in lagrange_mults],
            constraints_satisfied=constraints_satisfied,
            max_constraint_violation=round(max_violation, 6),
        )
