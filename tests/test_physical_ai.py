"""
Comprehensive Unit Test Suite for Physical AI Governor.
Pure Python 3.10+ standard library.
Verifies:
    1. Telemetry ingestion (MAVLink & ROS 2 / VLA)
    2. Control Barrier Functions (CBF torque clamping & proximity damping)
    3. Active-Set Quadratic Programming Solver (QP-CBF)
    4. High-Order Control Barrier Functions (HOCBF)
    5. Humanoid Stability Governor (ZMP & friction cone)
    6. Binary MAVLink v2 framing and CRC-16-MCRF4XX
    7. VLA action chunk horizon safety validation
    8. Merkle black-box audit ledger & cryptographic inclusion proofs
    9. Statutory Compliance Passports & EU AI Act Dossier Generation
    10. FAA Part 89 ASTM F3411-22a Remote ID broadcast synthesis
    11. Unified CLI commands
"""

import io
import json
import unittest
from unittest.mock import patch

from physical_ai_governor.cli import build_parser, main
from physical_ai_governor.control_barrier import (
    ControlBarrierFilter,
    HighOrderControlBarrierFilter,
    HumanoidStabilityGovernor,
    QPSafetyFilter,
)
from physical_ai_governor.evaluator import PhysicalAIBenchmarkRunner
from physical_ai_governor.mavlink_frame import (
    MAVLinkFrameParser,
    serialize_mavlink_v2_global_position,
)
from physical_ai_governor.merkle_blackbox import MerkleBlackBoxLedger
from physical_ai_governor.qp_solver import ActiveSetQPSolver
from physical_ai_governor.statutory_engine import StatutoryAssuranceEngine
from physical_ai_governor.telemetry_ingest import TelemetryIngestor
from physical_ai_governor.vla_validator import VLAActionHorizonValidator


class TestPhysicalAIGovernor(unittest.TestCase):
    """Rigorous verification of streaming physical AI safety and statutory assurance."""

    def setUp(self) -> None:
        self.ingestor = TelemetryIngestor()
        self.filter = ControlBarrierFilter(
            min_human_distance_m=1.50,
            max_joint_torque_nm=150.0,
            max_velocity_mps=4.0,
        )
        self.blackbox = MerkleBlackBoxLedger()
        self.runner = PhysicalAIBenchmarkRunner()

    def test_telemetry_ingestion_parsers(self) -> None:
        """Verifies parsing of MAVLink and ROS 2 packets."""
        drone_pkt = self.ingestor.parse_mavlink_quadrotor(
            drone_id="drone_01",
            timestamp_ns=1000,
            lat_lon_alt=(37.77, -122.41, 50.0),
            vel_ned=(1.2, 0.5, -0.1),
            human_proximity=15.0,
            battery=88.0,
            motor_thrusts=[18.0, 18.0, 18.0, 18.0],
        )
        self.assertEqual(drone_pkt.robot_type, "quadrotor_drone")
        self.assertEqual(len(drone_pkt.joint_torques), 4)

        humanoid_pkt = self.ingestor.parse_humanoid_joint_state(
            robot_id="humanoid_01",
            timestamp_ns=2000,
            base_pos=(0.0, 0.0, 1.2),
            base_vel=(0.2, 0.0, 0.0),
            current_torques=[30.0, -20.0],
            commanded_torques=[45.0, -35.0],
            human_proximity=3.0,
            battery=92.0,
        )
        self.assertEqual(humanoid_pkt.robot_type, "humanoid_biped")

    def test_control_barrier_torque_clamping(self) -> None:
        """Verifies excessive commanded torques are clamped to safe barrier."""
        unsafe_pkt = self.ingestor.parse_humanoid_joint_state(
            robot_id="humanoid_01",
            timestamp_ns=3000,
            base_pos=(0.0, 0.0, 1.2),
            base_vel=(0.0, 0.0, 0.0),
            current_torques=[0.0, 0.0],
            commanded_torques=[190.0, -210.0],  # Exceeds 150 Nm
            human_proximity=5.0,
            battery=90.0,
        )
        decision = self.filter.evaluate_safety(unsafe_pkt)
        self.assertFalse(decision.is_safe)
        self.assertTrue(decision.intervention_triggered)
        self.assertEqual(decision.filtered_command[0], 150.0)
        self.assertEqual(decision.filtered_command[1], -150.0)

    def test_control_barrier_human_proximity_damping(self) -> None:
        """Verifies human proximity breach triggers protective damping."""
        breach_pkt = self.ingestor.parse_humanoid_joint_state(
            robot_id="humanoid_01",
            timestamp_ns=4000,
            base_pos=(0.0, 0.0, 1.2),
            base_vel=(0.0, 0.0, 0.0),
            current_torques=[0.0],
            commanded_torques=[100.0],
            human_proximity=0.75,  # Less than 1.50m safe barrier
            battery=90.0,
        )
        decision = self.filter.evaluate_safety(breach_pkt)
        self.assertFalse(decision.is_safe)
        self.assertTrue(decision.intervention_triggered)
        self.assertLess(decision.filtered_command[0], 100.0)

    def test_merkle_blackbox_hash_chaining(self) -> None:
        """Verifies Merkle root computation over multiple records."""
        pkt = self.ingestor.parse_humanoid_joint_state("r1", 100, (0, 0, 1), (0, 0, 0), [10], [10], 2.0, 90)
        dec = self.filter.evaluate_safety(pkt)

        self.blackbox.append_record(pkt, dec)
        self.blackbox.append_record(pkt, dec)
        root = self.blackbox.build_merkle_root()

        self.assertEqual(len(root), 64)
        self.assertEqual(len(self.blackbox.leaf_hashes), 2)

    def test_compliance_passport_issuance(self) -> None:
        """Verifies statutory compliance passport fields and signature."""
        pkt = self.ingestor.parse_humanoid_joint_state("r1", 100, (0, 0, 1), (0, 0, 0), [10], [10], 2.0, 90)
        dec = self.filter.evaluate_safety(pkt)
        self.blackbox.append_record(pkt, dec)

        passport = self.blackbox.issue_compliance_passport("humanoid_01", total_interventions=0)
        self.assertEqual(passport.robot_id, "humanoid_01")
        self.assertEqual(passport.faa_part89_remote_id_status, "CERTIFIED_COMPLIANT")
        self.assertEqual(passport.eu_ai_act_annex_iii_status, "SAFETY_COMPONENT_VERIFIED")
        self.assertEqual(passport.iso10218_robot_safety_status, "FORWARD_INVARIANCE_CONFIRMED")
        self.assertEqual(len(passport.notary_signature), 64)

    def test_end_to_end_benchmark_runner(self) -> None:
        """Verifies 1000-cycle simulation throughput and zero unmitigated violations."""
        res = self.runner.run_benchmark(num_cycles=1000)
        self.assertEqual(res["total_telemetry_cycles"], 1000)
        self.assertGreater(res["cbf_safety_interventions"], 40)
        self.assertEqual(res["unmitigated_violations"], 0)
        self.assertEqual(res["safety_enforcement_rate"], 1.0)
        self.assertGreater(res["ingestion_throughput_pps"], 15_000.0)
        self.assertLess(res["benchmark_latency_ms"], 200.0)

    def test_qp_solver_unconstrained_and_constrained(self) -> None:
        """Verifies Active-Set QP optimization on strictly convex quadratic programs."""
        solver = ActiveSetQPSolver()
        # min 0.5 * (u0^2 + u1^2) - u0 - 2*u1
        # s.t. u0 + u1 <= 1, u >= 0
        P = [[1.0, 0.0], [0.0, 1.0]]
        q = [-1.0, -2.0]
        A = [[1.0, 1.0]]
        b = [1.0]
        u_min = [0.0, 0.0]
        u_max = [2.0, 2.0]

        sol = solver.solve(P, q, A, b, u_min, u_max)
        self.assertTrue(sol.converged)
        self.assertAlmostEqual(sol.u[0], 0.0, places=3)
        self.assertAlmostEqual(sol.u[1], 1.0, places=3)

    def test_qp_safety_filter(self) -> None:
        """Verifies QP-CBF minimal intervention filter on hazardous inputs."""
        qp_filter = QPSafetyFilter(min_human_distance_m=1.5, max_joint_torque_nm=150.0)
        pkt = self.ingestor.parse_humanoid_joint_state(
            "gr00t_01", 100, (0, 0, 1.2), (0, 0, 0), [0], [180.0, -210.0], 1.2, 95
        )
        dec = qp_filter.evaluate_safety_qp(pkt)
        self.assertTrue(dec.intervention_triggered)
        self.assertFalse(dec.is_safe)
        self.assertLessEqual(dec.filtered_command[0], 150.0)
        self.assertGreaterEqual(dec.filtered_command[1], -150.0)

    def test_high_order_control_barrier_filter(self) -> None:
        """Verifies relative-degree-2 HOCBF approach rate and deceleration damping."""
        hocbf = HighOrderControlBarrierFilter(safe_distance_m=1.50, max_deceleration_mps2=5.0)
        # Moving towards obstacle at 1.0 m/s when only 1.2m away -> requires safe deceleration
        is_safe, margin, filtered_accel = hocbf.evaluate_hocbf(
            relative_distance=1.2,
            approach_velocity=-1.0,
            commanded_acceleration=2.0,
        )
        self.assertFalse(is_safe)
        self.assertGreater(filtered_accel, 0.0)

    def test_humanoid_stability_governor(self) -> None:
        """Verifies Zero Moment Point (ZMP) and friction cone stability checks."""
        gov = HumanoidStabilityGovernor(friction_coefficient=0.6)
        # 1. Stable stance
        stable_state = gov.evaluate_stability(
            com_pos=(0.02, 0.01, 0.8),
            com_acc=(0.1, 0.05, 0.0),
            ground_reaction_force_xyz=(10.0, 5.0, 400.0),
            inter_link_distance_m=0.15,
        )
        self.assertTrue(stable_state.composite_stable)
        self.assertTrue(stable_state.zmp_inside_support)
        self.assertTrue(stable_state.friction_cone_satisfied)

        # 2. Slipping stance violating friction cone
        slip_state = gov.evaluate_stability(
            com_pos=(0.0, 0.0, 0.8),
            com_acc=(0.0, 0.0, 0.0),
            ground_reaction_force_xyz=(200.0, 200.0, 50.0),  # Tangential sqrt(2*200^2)=282 > 0.6*50=30
            inter_link_distance_m=0.15,
        )
        self.assertFalse(slip_state.friction_cone_satisfied)
        self.assertFalse(slip_state.composite_stable)

    def test_mavlink_binary_frame_and_crc(self) -> None:
        """Verifies MAVLink v2 binary serialization, parsing, and CRC-16 checksum."""
        raw = serialize_mavlink_v2_global_position(
            sysid=1, compid=1, seq=10, time_boot_ms=50000,
            lat=37.7749, lon=-122.4194, alt_m=120.0,
            vx_mps=2.5, vy_mps=0.0, vz_mps=-0.5,
        )
        parser = MAVLinkFrameParser()
        msg = parser.parse_frame(raw)
        self.assertIsNotNone(msg)
        self.assertTrue(msg.is_valid_crc)
        self.assertEqual(msg.msgid, 33)

        pkt = parser.parse_to_telemetry_packet(raw, drone_id="drone_alpha", human_proximity=8.5)
        self.assertIsNotNone(pkt)
        self.assertEqual(pkt.robot_id, "drone_alpha")
        self.assertEqual(pkt.position_xyz[0], 37.7749)
        self.assertEqual(pkt.velocity_xyz[0], 2.5)

    def test_vla_action_horizon_validator(self) -> None:
        """Verifies VLA multi-step chunk safety screening and predictive correction."""
        validator = VLAActionHorizonValidator(min_human_distance_m=1.5, max_joint_torque_nm=150.0)
        init_pkt = self.ingestor.parse_humanoid_joint_state(
            "gr00t_01", 1000, (0, 0, 1.2), (0, 0, 0), [0, 0], [0, 0], 10.0, 95.0
        )
        # Chunk of 8 steps with excessive torque at step 4
        chunk = [[40.0, 30.0]] * 4 + [[210.0, -220.0]] + [[40.0, 30.0]] * 3
        res = validator.validate_and_filter_chunk(init_pkt, chunk)
        self.assertFalse(res.is_chunk_safe)
        self.assertEqual(res.first_violation_step, 4)
        self.assertLessEqual(max(abs(t) for t in res.safe_action_chunk[4]), 150.0)

    def test_merkle_audit_proof_generation_and_verification(self) -> None:
        """Verifies Merkle inclusion proof paths and cryptographic verification."""
        leaves = []
        for i in range(8):
            pkt = self.ingestor.parse_humanoid_joint_state(f"r{i}", i * 100, (0, 0, 1), (0, 0, 0), [10], [10], 2.0, 90)
            dec = self.filter.evaluate_safety(pkt)
            leaves.append(self.blackbox.append_record(pkt, dec))

        root = self.blackbox.build_merkle_root()
        for idx, leaf in enumerate(leaves):
            proof = self.blackbox.generate_audit_proof(idx)
            self.assertTrue(MerkleBlackBoxLedger.verify_audit_proof(leaf, proof, root))

        # Tampered leaf fails
        tampered = leaves[0][:-2] + "ff"
        proof0 = self.blackbox.generate_audit_proof(0)
        self.assertFalse(MerkleBlackBoxLedger.verify_audit_proof(tampered, proof0, root))

    def test_statutory_engine_faa_eu_iso(self) -> None:
        """Verifies FAA Remote ID broadcast, EU AI Act dossier, and ISO/TS 15066 checks."""
        engine = StatutoryAssuranceEngine()

        # FAA Part 89 Remote ID
        rid = engine.synthesize_faa_part89_remote_id(37.7749, -122.4194, 100.0, 5.0)
        self.assertEqual(rid["payload_bytes_length"], 25)
        self.assertEqual(rid["broadcast_status"], "BROADCAST_READY")

        # EU AI Act Annex III Dossier
        passport = self.blackbox.issue_compliance_passport("gr00t_01", total_interventions=2)
        dossier = engine.generate_eu_ai_act_annex_iii_dossier(passport)
        self.assertEqual(dossier["document_type"], "EU_AI_ACT_ANNEX_III_CONFORMITY_DOSSIER")
        self.assertIn("High-Risk AI System", dossier["system_profile"]["classification"])

        # ISO/TS 15066 Biomechanical force limit
        ok, limit, margin = engine.check_iso15066_biomechanical_limit("chest", 110.0)
        self.assertTrue(ok)
        self.assertEqual(limit, 140.0)
        self.assertEqual(margin, 30.0)

    def test_cli_commands(self) -> None:
        """Verifies CLI parser and command execution."""
        # Test benchmark CLI command
        parser = build_parser()
        args = parser.parse_args(["benchmark", "--cycles", "50", "--json"])
        self.assertEqual(args.cycles, 50)
        self.assertTrue(args.json)

        ret = main(["benchmark", "--cycles", "20", "--json"])
        self.assertEqual(ret, 0)

        ret_vla = main(["vla-eval", "--horizon", "4", "--human-dist", "5.0"])
        self.assertEqual(ret_vla, 0)

        ret_rid = main(["remote-id", "--speed", "4.5"])
        self.assertEqual(ret_rid, 0)


if __name__ == "__main__":
    unittest.main()
