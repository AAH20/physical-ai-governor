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
import pathlib
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
        self.assertEqual(passport.faa_part89_remote_id_status, "FAA_MOC_DOC_REQUIRED")
        self.assertEqual(passport.eu_ai_act_annex_iii_status, "CONTROL_EVIDENCE_GENERATED")
        self.assertEqual(passport.iso10218_robot_safety_status, "SYNTHETIC_TEST_PASSED")
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

    def test_qp_safety_filter_with_control_matrix(self) -> None:
        """Verifies QP-CBF incorporates control_matrix_g Lie derivative constraints."""
        qp_filter = QPSafetyFilter(min_human_distance_m=1.5, max_joint_torque_nm=150.0)
        pkt = self.ingestor.parse_humanoid_joint_state(
            "gr00t_01", 100, (0, 0, 1.2), (0.5, 0, 0), [0], [120.0, -110.0], 1.2, 95
        )
        # 2 control inputs, control matrix g provides Lie derivative row that forces intervention
        control_matrix_g = [[-0.8, 0.6]]
        dec = qp_filter.evaluate_safety_qp(pkt, control_matrix_g=control_matrix_g)
        self.assertIsNotNone(dec)
        self.assertTrue(dec.intervention_triggered)
        self.assertFalse(dec.is_safe)
        self.assertIn("control_matrix_g", dec.violation_reason if dec.violation_reason else "")

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

        ret_claw = main(["grc-claw-sync", "--cycles", "5"])
        self.assertEqual(ret_claw, 0)

        ret_zk = main(["zk-prove", "--robot-id", "test_bot", "--cycles", "5"])
        self.assertEqual(ret_zk, 0)

        ret_swarm = main(["swarm-eval", "--agents", "3"])
        self.assertEqual(ret_swarm, 0)

    def test_grc_claw_canonical_and_evidence_packaging(self) -> None:
        """Verifies RFC 8785 canonical digest and GRC_Claw EvidenceStore packaging."""
        from physical_ai_governor.grc_claw_bridge import (
            GRCClawBridge,
            canonical_json,
            compute_canonical_digest,
        )

        d = {"z": 10, "a": [3, 2, 1], "nested": {"b": True, "a": None}}
        canon = canonical_json(d)
        self.assertEqual(canon, '{"a":[3,2,1],"nested":{"a":null,"b":true},"z":10}')
        digest = compute_canonical_digest(d)
        self.assertEqual(len(digest), 64)

        bridge = GRCClawBridge(gateway_url="http://127.0.0.1:18791", tenant_id=42)
        passport = self.blackbox.issue_compliance_passport("humanoid_01", total_interventions=1)
        evidence = bridge.build_evidence_record(passport)

        self.assertEqual(evidence.tenantId, 42)
        self.assertIn("rbb://humanoid_01/passport/", evidence.uri)
        self.assertEqual(len(evidence.sha256), 64)

        iso42001 = bridge.assess_iso42001_readiness(passport)
        self.assertEqual(iso42001["overall_iso42001_readiness"], "CONTROL_EVIDENCE_GENERATED")

        # Offline sync returns OFFLINE_QUEUED or ONLINE_SYNC_SUCCESS
        res = bridge.sync_to_gateway(evidence)
        self.assertIn(res["status"], ["OFFLINE_QUEUED", "ONLINE_SYNC_SUCCESS"])

    def test_grc_claw_rbb_event_stream(self) -> None:
        """Verifies real-time event stream translation into robot-black-box-contract events."""
        from physical_ai_governor.grc_claw_bridge import GRCClawBridge

        bridge = GRCClawBridge()
        pkt = self.ingestor.parse_humanoid_joint_state(
            "gr00t_01", 1000, (0, 0, 1.2), (0.2, 0, 0), [30], [180], 1.2, 95
        )
        dec = self.filter.evaluate_safety(pkt)
        stream_payload = bridge.format_rbb_event_stream(pkt, dec, sequence=5)

        self.assertEqual(stream_payload["schema_version"], "1.0.0-local.1")
        self.assertEqual(stream_payload["sequence"], 5)
        self.assertEqual(len(stream_payload["events"]), 4)
        event_types = [e["event_type"] for e in stream_payload["events"]]
        self.assertIn("observation.recorded", event_types)
        self.assertIn("proposal.recorded", event_types)
        self.assertIn("approval.recorded", event_types)
        self.assertIn("execution.observed", event_types)

    def test_iso10218_safety_state_machine(self) -> None:
        """Verifies collaborative speed reduction, protective stop, and emergency stop."""
        from physical_ai_governor.safety_state_machine import (
            ISO10218SafetyStateMachine,
            RobotSafetyState,
        )

        sm = ISO10218SafetyStateMachine(
            stop_distance_m=0.5,
            collaborative_distance_m=1.5,
            max_collaborative_speed_mps=0.25,
        )

        # 1. Normal state (distance 3.0m)
        pkt_normal = self.ingestor.parse_humanoid_joint_state("r1", 100, (0, 0, 1), (0.1, 0, 0), [10], [50.0], 3.0, 90)
        state, torques = sm.update(pkt_normal)
        self.assertEqual(state, RobotSafetyState.NORMAL_AUTONOMOUS)
        self.assertEqual(torques, [50.0])

        # 2. Collaborative zone (distance 1.2m, speed 0.5m/s -> clamped)
        pkt_collab = self.ingestor.parse_humanoid_joint_state("r1", 200, (0, 0, 1), (0.5, 0, 0), [10], [50.0], 1.2, 90)
        state, torques = sm.update(pkt_collab)
        self.assertEqual(state, RobotSafetyState.REDUCED_SPEED_COLLABORATIVE)
        self.assertLess(torques[0], 50.0)

        # 3. Protective Stop zone (distance 0.3m -> zero torque)
        pkt_stop = self.ingestor.parse_humanoid_joint_state("r1", 300, (0, 0, 1), (0, 0, 0), [10], [50.0], 0.3, 90)
        state, torques = sm.update(pkt_stop)
        self.assertEqual(state, RobotSafetyState.PROTECTIVE_STOP)
        self.assertEqual(torques, [0.0])

        # 4. Emergency Stop
        sm.trigger_emergency_stop("Hardware Fault")
        self.assertEqual(sm.current_state, RobotSafetyState.EMERGENCY_STOP)
        self.assertEqual(len(sm.transitions), 3)

    def test_telemetry_stream_server_processing(self) -> None:
        """Verifies high-frequency in-memory stream processing and ledger notarization."""
        from physical_ai_governor.telemetry_stream import TelemetryStreamServer

        server = TelemetryStreamServer()
        req_json = json.dumps({
            "robot_id": "stream_robot",
            "timestamp_ns": 1000,
            "position_xyz": [0, 0, 1],
            "velocity_xyz": [0, 0, 0],
            "joint_torques": [10],
            "human_distance_meters": 2.0,
            "battery_percentage": 95,
            "command_torque_input": [190.0],
        })

        res = server.process_telemetry_json(req_json)
        self.assertTrue(res["intervention_triggered"])
        self.assertEqual(res["filtered_command"], [150.0])
        self.assertEqual(len(res["leaf_hash"]), 64)
        self.assertEqual(server.total_processed_packets, 1)

    def test_blinded_safety_prover_and_verifier(self) -> None:
        """Verifies blinded cryptographic commitment envelope generation and verification."""
        from physical_ai_governor.zk_proof import ZKSafetyProver

        pkt = self.ingestor.parse_humanoid_joint_state(
            robot_id="stealth_bot",
            timestamp_ns=1000,
            base_pos=(0.0, 0.0, 1.0),
            base_vel=(0.0, 0.0, 0.0),
            current_torques=[10.0],
            commanded_torques=[10.0],
            human_proximity=3.5,
            battery=90.0,
        )
        dec = self.filter.evaluate_safety(pkt)
        self.blackbox.append_record(pkt, dec)

        prover = ZKSafetyProver()
        envelope = prover.generate_zk_proof(self.blackbox, robot_id="stealth_bot")
        self.assertEqual(envelope.robot_id, "stealth_bot")
        self.assertGreater(envelope.total_cycles_proven, 0)
        self.assertTrue(ZKSafetyProver.verify_zk_proof(envelope))

        # Tampered envelope fails
        tampered_env = envelope
        tampered_env.challenge_hash = "0" * 64
        self.assertFalse(ZKSafetyProver.verify_zk_proof(tampered_env))

    def test_simulated_tpm_attestation(self) -> None:
        """Verifies simulated TPM 2.0 PCR register measurement and synthetic quote verification."""
        from physical_ai_governor.hardware_tpm import TPM2HardwareAttestor

        tpm = TPM2HardwareAttestor(silicon_chip_id="JETSON-ORIN-TEST")
        pcr10 = tpm.measure_code_integrity("def evaluate_safety(): ...")
        pcr11 = tpm.measure_policy_limits(1.5, 150.0, 4.0)

        self.assertEqual(len(pcr10), 64)
        self.assertEqual(len(pcr11), 64)

        passport = self.blackbox.issue_compliance_passport("jetson_bot", total_interventions=0)
        quote = tpm.seal_merkle_passport(passport)

        self.assertEqual(quote.silicon_chip_id, "JETSON-ORIN-TEST")
        self.assertTrue(tpm.verify_tpm_quote(quote))

    def test_swarm_control_barrier_governor(self) -> None:
        """Verifies multi-agent reciprocal pairwise collision avoidance."""
        from physical_ai_governor.swarm_cbf import (
            SwarmAgentState,
            SwarmControlBarrierGovernor,
        )

        gov = SwarmControlBarrierGovernor(min_inter_agent_distance_m=2.0)
        agent1 = SwarmAgentState("d1", (0.0, 0.0, 10.0), (1.5, 0.0, 0.0), (1.5, 0.0, 0.0))
        agent2 = SwarmAgentState("d2", (1.2, 0.0, 10.0), (-1.5, 0.0, 0.0), (-1.5, 0.0, 0.0))

        decisions = gov.evaluate_swarm_safety([agent1, agent2])
        self.assertTrue(decisions["d1"].intervened)
        self.assertTrue(decisions["d2"].intervened)
        self.assertIn("d2", decisions["d1"].threat_agent_ids)
        self.assertIn("d1", decisions["d2"].threat_agent_ids)

    def test_ros2_telemetry_bridge_conversions(self) -> None:
        """Verifies ROS 2 JointState message conversions and diagnostic arrays."""
        from physical_ai_governor.ros2_bridge import ROS2JointState, ROS2TelemetryBridge

        bridge = ROS2TelemetryBridge()
        msg = ROS2JointState(
            names=["j1", "j2"],
            positions=[0.1, -0.2],
            velocities=[0.0, 0.0],
            efforts=[25.0, -20.0],
            stamp_sec=1700000000,
            stamp_nanosec=100000,
        )

        decision, leaf, diag = bridge.process_ros2_cycle(
            msg=msg,
            robot_id="humanoid_ros2",
            commanded_efforts=[180.0, -190.0],
            human_proximity_m=1.0,
        )

        self.assertFalse(decision.is_safe)
        self.assertEqual(diag["level"], 1)
        self.assertEqual(len(leaf), 64)

    def test_ros2_telemetry_bridge_multi_cycle(self) -> None:
        """Verifies ROS 2 Telemetry Bridge executes multiple consecutive cycles without crashing."""
        from physical_ai_governor.ros2_bridge import ROS2JointState, ROS2TelemetryBridge

        bridge = ROS2TelemetryBridge()
        msg = ROS2JointState(
            names=["j1", "j2"],
            positions=[0.1, -0.2],
            velocities=[0.0, 0.0],
            efforts=[25.0, -20.0],
            stamp_sec=1700000000,
            stamp_nanosec=100000,
        )

        for cycle in range(25):
            decision, leaf, diag = bridge.process_ros2_cycle(
                msg=msg,
                robot_id="humanoid_ros2",
                commanded_efforts=[40.0, -30.0],
                human_proximity_m=3.0,
            )
            self.assertTrue(decision.is_safe)
            self.assertEqual(diag["level"], 0)
            self.assertEqual(len(leaf), 64)

    def test_rbb_canonical_serialization_and_validation(self) -> None:
        """Verifies RFC 8785 canonical JSON serialization and RBB event schema validation."""
        import tempfile
        from physical_ai_governor.rbb_contract import (
            canonical_json,
            compute_rbb_digest,
            validate_rbb_event,
        )

        obj = {"z": 1, "a": [2, 1], "nested": {"b": True, "a": None}}
        canon = canonical_json(obj)
        self.assertEqual(canon, '{"a":[2,1],"nested":{"a":null,"b":true},"z":1}')
        digest = compute_rbb_digest(obj)
        self.assertEqual(len(digest), 64)

        # Non-finite floats rejected
        with self.assertRaises(ValueError):
            canonical_json({"inf": float("inf")})

    def test_rbb_recorder_and_verifier_bundle_integrity(self) -> None:
        """Verifies full recording of telemetry cycles into an RBB bundle and offline verification."""
        import tempfile
        from physical_ai_governor.rbb_recorder import RobotBlackBoxRecorder
        from physical_ai_governor.rbb_verifier import RobotBlackBoxVerifier

        with tempfile.TemporaryDirectory() as tmp_dir:
            bundle_dir = f"{tmp_dir}/test_rbb_bundle"
            recorder = RobotBlackBoxRecorder(robot_id="humanoid_alpha", tenant_ref="tenant-test")
            recorder.start_run(task="benign_block_handover")

            for i in range(4):
                pkt = self.ingestor.parse_humanoid_joint_state(
                    robot_id="humanoid_alpha",
                    timestamp_ns=i * 1_000_000,
                    base_pos=(0.0, 0.0, 1.2),
                    base_vel=(0.1, 0.0, 0.0),
                    current_torques=[20.0, -15.0],
                    commanded_torques=[30.0, -25.0] if i < 3 else [190.0, -210.0],
                    human_proximity=2.5 if i < 3 else 1.2,
                    battery=95.0,
                )
                dec = self.filter.evaluate_safety(pkt)
                recorder.record_safety_cycle(pkt, dec)

            recorder.close_run()
            res = recorder.export_bundle(bundle_dir)

            self.assertEqual(res["run_id"], recorder.run_id)
            self.assertGreater(res["total_events"], 10)

            # 1. Audit in fail-closed default mode WITHOUT keys -> fails closed
            unauth_report = RobotBlackBoxVerifier.verify_bundle(bundle_dir)
            self.assertFalse(unauth_report.is_valid)
            self.assertFalse(unauth_report.is_authenticated)
            self.assertTrue(any("AUTHENTICATION_REQUIRED" in err for err in unauth_report.errors))

            # 2. Audit in INTEGRITY_ONLY mode -> passes internal coherence, unauthenticated
            integ_report = RobotBlackBoxVerifier.verify_bundle(bundle_dir, trust_mode="INTEGRITY_ONLY")
            self.assertTrue(integ_report.is_valid, f"Integrity report errors: {integ_report.errors}")
            self.assertFalse(integ_report.is_authenticated)
            self.assertIn("events_cryptographic_hash_chain_valid", integ_report.checks_passed)

            # 3. Audit in AUTHENTICATED mode with external trusted keys -> fully authenticates
            report = RobotBlackBoxVerifier.verify_bundle(
                bundle_dir,
                trust_mode="AUTHENTICATED",
                external_trusted_keys=recorder.get_trusted_keys(),
            )
            self.assertTrue(report.is_valid, f"Expected valid bundle, got errors: {report.errors}")
            self.assertTrue(report.is_authenticated)
            self.assertEqual(report.total_events, res["total_events"])
            self.assertIn("events_cryptographic_hash_chain_valid", report.checks_passed)
            self.assertIn("witness_consensus_head_verified", report.checks_passed)
            self.assertIn("external_cryptographic_signatures_authenticated", report.checks_passed)

            # Test detection of tampered bundle (flip a byte in events.ndjson)
            events_file = pathlib.Path(bundle_dir) / "events.ndjson"
            raw = events_file.read_bytes()
            events_file.write_bytes(raw[:-10] + b"tampered!!\n")

            tampered_report = RobotBlackBoxVerifier.verify_bundle(
                bundle_dir,
                trust_mode="AUTHENTICATED",
                external_trusted_keys=recorder.get_trusted_keys(),
            )
            self.assertFalse(tampered_report.is_valid)
            self.assertGreater(len(tampered_report.errors), 0)

    def test_rbb_verifier_detects_scope_tampering(self) -> None:
        """
        Verifies that RobotBlackBoxVerifier detects payload tampering even if
        events.ndjson SHA-256 and manifest.json are maliciously recalculated.
        Directly validates defense against unauthorized scope mutation.
        """
        import tempfile
        from physical_ai_governor.rbb_contract import canonical_json, sha256_hex
        from physical_ai_governor.rbb_recorder import RobotBlackBoxRecorder
        from physical_ai_governor.rbb_verifier import RobotBlackBoxVerifier

        with tempfile.TemporaryDirectory() as tmp_dir:
            bundle_dir = f"{tmp_dir}/attack_bundle"
            recorder = RobotBlackBoxRecorder(robot_id="humanoid_scope_test", tenant_ref="tenant-test")
            recorder.start_run(task="benign_block_handover")

            pkt = self.ingestor.parse_humanoid_joint_state(
                robot_id="humanoid_scope_test",
                timestamp_ns=1000,
                base_pos=(0.0, 0.0, 1.2),
                base_vel=(0.1, 0.0, 0.0),
                current_torques=[20.0, -15.0],
                commanded_torques=[30.0, -25.0],
                human_proximity=2.5,
                battery=95.0,
            )
            dec = self.filter.evaluate_safety(pkt)
            recorder.record_safety_cycle(pkt, dec)
            recorder.close_run()
            res = recorder.export_bundle(bundle_dir)

            # Legitimate bundle must verify with external keys
            initial_report = RobotBlackBoxVerifier.verify_bundle(
                bundle_dir,
                trust_mode="AUTHENTICATED",
                external_trusted_keys=recorder.get_trusted_keys(),
            )
            self.assertTrue(initial_report.is_valid)

            # Attacker mutates requested_scope in proposal.recorded event
            events_file = pathlib.Path(bundle_dir) / "events.ndjson"
            lines = events_file.read_text().splitlines()
            mutated_lines = []
            mutated_count = 0
            for line in lines:
                evt = json.loads(line)
                if evt.get("event_type") == "proposal.recorded":
                    evt["payload"]["requested_scope"] = "UNAUTHORIZED_CHANGED_SCOPE"
                    mutated_count += 1
                mutated_lines.append(canonical_json(evt))
            self.assertGreater(mutated_count, 0)

            new_events_bytes = ("\n".join(mutated_lines) + "\n").encode("utf-8")
            events_file.write_bytes(new_events_bytes)

            # Attacker updates manifest.json with the new events_digest to bypass raw file check
            manifest_file = pathlib.Path(bundle_dir) / "manifest.json"
            manifest = json.loads(manifest_file.read_text())
            manifest["events_digest"] = sha256_hex(new_events_bytes)
            manifest_body = {k: v for k, v in manifest.items() if k != "authentication"}
            manifest["authentication"]["event_digest"] = sha256_hex(canonical_json(manifest_body).encode("utf-8"))
            manifest_file.write_bytes(canonical_json(manifest).encode("utf-8"))

            # Verifier MUST catch the tampered body via recomputed event body digest
            audit_report = RobotBlackBoxVerifier.verify_bundle(
                bundle_dir,
                trust_mode="INTEGRITY_ONLY",
            )
            self.assertFalse(audit_report.is_valid, "Verifier failed to detect tampered requested_scope payload!")
            self.assertTrue(
                any("BODY_TAMPERED" in err or "body digest mismatch" in err for err in audit_report.errors),
                f"Expected BODY_TAMPERED error, got: {audit_report.errors}",
            )

    def test_rbb_cli_commands(self) -> None:
        """Verifies RBB CLI recording and offline verification commands."""
        import tempfile
        from physical_ai_governor.cli import main

        with tempfile.TemporaryDirectory() as tmp_dir:
            bundle_dir = f"{tmp_dir}/cli_rbb_bundle"
            ret_rec = main(["rbb-record", "--robot-id", "humanoid_cli", "--cycles", "3", "--out", bundle_dir])
            self.assertEqual(ret_rec, 0)

            # Integrity-only check passes without keys
            ret_ver_integ = main(["rbb-verify", "--bundle", bundle_dir, "--trust-mode", "INTEGRITY_ONLY", "--json"])
            self.assertEqual(ret_ver_integ, 0)

            # Default authenticated check fails closed without external keys
            ret_ver_auth = main(["rbb-verify", "--bundle", bundle_dir, "--json"])
            self.assertEqual(ret_ver_auth, 2)

            ret_inc = main(["incident-report", "--bundle", bundle_dir, "--json"])
            self.assertEqual(ret_inc, 0)

        ret_kino = main(["kinodynamics-eval", "--joint1", "0.5", "--joint2", "0.4", "--joint3", "-0.2"])
        self.assertEqual(ret_kino, 0)

    def test_rbb_verifier_rejects_fully_rewritten_bundle_without_external_trust(self) -> None:
        """
        Adversarial audit check:
        Attacker takes an RBB bundle, generates fresh keys, replaces all signatures,
        and recomputes all hash chains.
        Verifier MUST reject the bundle in fail-closed default mode, and MUST reject
        it when audited against the legitimate operator's external trusted keys.
        """
        import tempfile
        from physical_ai_governor.rbb_contract import canonical_json, sha256_hex
        from physical_ai_governor.rbb_recorder import RobotBlackBoxRecorder
        from physical_ai_governor.rbb_verifier import RobotBlackBoxVerifier

        with tempfile.TemporaryDirectory() as tmp_dir:
            bundle_dir = f"{tmp_dir}/rewritten_bundle"
            recorder = RobotBlackBoxRecorder(robot_id="drone_target", tenant_ref="tenant-sky")
            recorder.start_run(task="delivery_flight")
            pkt = self.ingestor.parse_humanoid_joint_state(
                robot_id="drone_target",
                timestamp_ns=1000,
                base_pos=(0.0, 0.0, 1.2),
                base_vel=(2.0, 0.0, 0.0),
                current_torques=[10.0],
                commanded_torques=[10.0],
                human_proximity=10.0,
                battery=90.0,
            )
            dec = self.filter.evaluate_safety(pkt)
            recorder.record_safety_cycle(pkt, dec)
            recorder.close_run()
            recorder.export_bundle(bundle_dir)

            legit_keys = recorder.get_trusted_keys()

            # Attacker creates a fresh attacker-controlled recorder and overwrites trust.json
            attacker_recorder = RobotBlackBoxRecorder(
                robot_id="drone_target",
                signing_key_id="attacker-key-99",
                witness_key_id="attacker-witness-99",
            )

            # Default verify without keys -> FAIL CLOSED
            unauth_report = RobotBlackBoxVerifier.verify_bundle(bundle_dir)
            self.assertFalse(unauth_report.is_valid)
            self.assertFalse(unauth_report.is_authenticated)
            self.assertTrue(any("AUTHENTICATION_REQUIRED" in e for e in unauth_report.errors))

            # Attacker rewrites manifest to be signed by attacker-key-99
            manifest_file = pathlib.Path(bundle_dir) / "manifest.json"
            manifest = json.loads(manifest_file.read_text())
            manifest_body = {k: v for k, v in manifest.items() if k != "authentication"}
            signed_manifest = attacker_recorder._sign_record(manifest_body, "MANIFEST")
            manifest_file.write_bytes(canonical_json(signed_manifest).encode("utf-8"))

            # Audited against legitimate operator keys -> REJECTED (untrusted key)
            audit_report = RobotBlackBoxVerifier.verify_bundle(
                bundle_dir,
                trust_mode="AUTHENTICATED",
                external_trusted_keys=legit_keys,
            )
            self.assertFalse(audit_report.is_valid)
            self.assertFalse(audit_report.is_authenticated)
            self.assertTrue(any("untrusted or missing key_id" in e or "signature verification failed" in e for e in audit_report.errors))

    def test_rbb_verifier_rejects_self_signed_witness(self) -> None:
        """Verifies that bundles where witness key equals producer key are rejected unless explicitly allowed."""
        import tempfile
        from physical_ai_governor.rbb_recorder import RobotBlackBoxRecorder
        from physical_ai_governor.rbb_verifier import RobotBlackBoxVerifier

        with tempfile.TemporaryDirectory() as tmp_dir:
            bundle_dir = f"{tmp_dir}/self_witness_bundle"
            # Self-signed recorder (producer key == witness key)
            recorder = RobotBlackBoxRecorder(
                robot_id="bot_self",
                signing_key_id="common-key-01",
                witness_key_id="common-key-01",
            )
            recorder.start_run(task="self_witness_test")
            pkt = self.ingestor.parse_humanoid_joint_state(
                robot_id="bot_self",
                timestamp_ns=1000,
                base_pos=(0.0, 0.0, 1.0),
                base_vel=(0.0, 0.0, 0.0),
                current_torques=[10.0],
                commanded_torques=[10.0],
                human_proximity=3.0,
                battery=90.0,
            )
            dec = self.filter.evaluate_safety(pkt)
            recorder.record_safety_cycle(pkt, dec)
            recorder.close_run()
            recorder.export_bundle(bundle_dir)

            report = RobotBlackBoxVerifier.verify_bundle(
                bundle_dir,
                trust_mode="AUTHENTICATED",
                external_trusted_keys=recorder.get_trusted_keys(),
                allow_self_witness=False,
            )
            self.assertFalse(report.is_valid)
            self.assertTrue(any("INDEPENDENT_WITNESS_REQUIRED" in e for e in report.errors))

    def test_qp_solver_detects_contradictory_infeasibility(self) -> None:
        """Verifies that ActiveSetQPSolver identifies contradictory/infeasible constraints and returns converged=False."""
        from physical_ai_governor.qp_solver import ActiveSetQPSolver

        solver = ActiveSetQPSolver()
        # Contradictory box constraints: u_min=100, u_max=-100
        sol = solver.solve(
            P=[[1.0]],
            q=[0.0],
            u_min=[100.0],
            u_max=[-100.0],
        )
        self.assertFalse(sol.converged)
        self.assertFalse(sol.constraints_satisfied)

        # Contradictory linear inequality: u >= 10 and u <= -10
        # -u <= -10  (u >= 10)
        #  u <= -10
        sol_ineq = solver.solve(
            P=[[1.0]],
            q=[0.0],
            A=[[-1.0], [1.0]],
            b=[-10.0, -10.0],
        )
        self.assertFalse(sol_ineq.converged)
        self.assertFalse(sol_ineq.constraints_satisfied)

    def test_qp_safety_filter_failsafe_on_infeasible_constraints(self) -> None:
        """Verifies that infeasible CBF/box constraints trigger a fail-safe protective stop."""
        from physical_ai_governor.control_barrier import QPSafetyFilter

        cbf_qp = QPSafetyFilter(min_human_distance_m=1.50)
        # Construct telemetry packet at proximity with velocity towards hazard
        pkt = self.ingestor.parse_humanoid_joint_state(
            robot_id="infeasible_bot",
            timestamp_ns=1000,
            base_pos=(0.0, 0.0, 0.0),
            base_vel=(10.0, 0.0, 0.0),
            current_torques=[50.0],
            commanded_torques=[50.0],
            human_proximity=1.50,  # h_prox = 0
            battery=90.0,
        )
        # Contradictory control matrix: row 0 forces u >= 10, row 1 forces u <= -10
        control_matrix_infeasible = [
            [1.0],   # -1 * u <= -10 => u >= 10
            [-1.0],  #  1 * u <= -10 => u <= -10
        ]
        dec = cbf_qp.evaluate_safety_qp(pkt, control_matrix_g=control_matrix_infeasible)
        self.assertEqual(dec.decision_status, "INFEASIBLE")
        self.assertTrue(dec.intervention_triggered)
        self.assertEqual(dec.filtered_command, [0.0])  # Protective stop commanded

    def test_qp_safety_filter_handles_invalid_nan_inputs(self) -> None:
        """Verifies that NaN and Inf control inputs trigger a protective stop with INVALID_INPUT status."""
        from physical_ai_governor.control_barrier import QPSafetyFilter

        cbf_qp = QPSafetyFilter()
        pkt_nan = self.ingestor.parse_humanoid_joint_state(
            robot_id="nan_bot",
            timestamp_ns=1000,
            base_pos=(0.0, 0.0, 1.0),
            base_vel=(0.0, 0.0, 0.0),
            current_torques=[10.0],
            commanded_torques=[float("nan")],
            human_proximity=2.0,
            battery=90.0,
        )
        dec_nan = cbf_qp.evaluate_safety_qp(pkt_nan)
        self.assertEqual(dec_nan.decision_status, "INVALID_INPUT")
        self.assertTrue(dec_nan.intervention_triggered)
        self.assertEqual(dec_nan.filtered_command, [0.0])

        pkt_inf = self.ingestor.parse_humanoid_joint_state(
            robot_id="inf_bot",
            timestamp_ns=1000,
            base_pos=(0.0, 0.0, 1.0),
            base_vel=(0.0, 0.0, 0.0),
            current_torques=[10.0],
            commanded_torques=[float("inf")],
            human_proximity=2.0,
            battery=90.0,
        )
        dec_inf = cbf_qp.evaluate_safety_qp(pkt_inf)
        self.assertEqual(dec_inf.decision_status, "INVALID_INPUT")
        self.assertTrue(dec_inf.intervention_triggered)
        self.assertEqual(dec_inf.filtered_command, [0.0])

    def test_vla_adversarial_guard_and_uncertainty_inflation(self) -> None:
        """Verifies dynamic barrier distance expansion and high-jerk adversarial smoothing."""
        from physical_ai_governor.vla_adversarial_guard import (
            VLAAdversarialGuard,
            VLAUncertaintyMetric,
        )

        guard = VLAAdversarialGuard(base_min_human_distance_m=1.50)

        # 1. Uncertainty barrier inflation
        high_unc = VLAUncertaintyMetric(epistemic_variance=0.8, perceptual_noise_ratio=0.7, ood_detection_score=0.9)
        d_inflated = guard.compute_dynamic_barrier_distance(high_unc.composite_uncertainty)
        self.assertGreater(d_inflated, 1.50)
        self.assertLessEqual(d_inflated, 1.50 * 2.5)

        # 2. Adversarial action chunk with extreme torque rate & jerk spikes
        curr_torques = [10.0, -10.0]
        # Spike from 10 to 200 in 0.05s -> rate = 3800 Nm/s >> 300 Nm/s
        adversarial_chunk = [
            [200.0, -200.0],
            [-180.0, 190.0],
            [150.0, -150.0],
        ]
        report = guard.evaluate_and_filter_chunk(
            current_torques=curr_torques,
            action_chunk=adversarial_chunk,
            dt_step_s=0.05,
            uncertainty=high_unc,
        )
        self.assertFalse(report.is_safe)
        self.assertGreater(len(report.adversarial_flags), 0)
        self.assertLessEqual(report.safe_action_chunk[0][0], 10.0 + (300.0 * 0.05) + 0.1)

    def test_whole_body_kinodynamics_and_singularity_avoidance(self) -> None:
        """Verifies Yoshikawa manipulability barrier and self-collision velocity clamping."""
        from physical_ai_governor.whole_body_kinodynamics import WholeBodyKinodynamicsGovernor

        gov = WholeBodyKinodynamicsGovernor(min_manipulability=0.05, min_self_collision_distance_m=0.15)

        # 1. Normal safe posture
        safe_links = {
            "left_hand": (0.3, 0.2, 0.8),
            "right_hand": (0.3, -0.2, 0.8),
            "torso": (0.0, 0.0, 0.8),
        }
        res_safe = gov.evaluate_whole_body_safety(safe_links, [0.4, 0.3, 0.2], [1.0, -1.0, 0.5])
        self.assertTrue(res_safe.is_safe)
        self.assertGreater(res_safe.manipulability_index, 0.05)

        # 2. Self-collision proximity: hands nearly touching (dist = 0.05m < 0.15m)
        colliding_links = {
            "left_hand": (0.3, 0.02, 0.8),
            "right_hand": (0.3, -0.03, 0.8),
            "torso": (0.0, 0.0, 0.8),
        }
        res_col = gov.evaluate_whole_body_safety(colliding_links, [0.4, 0.3, 0.2], [1.0, -1.0, 0.5])
        self.assertFalse(res_col.is_safe)
        self.assertIn("SELF_COLLISION_BREACH", res_col.interventions[0])
        self.assertEqual(res_col.filtered_joint_velocities, [0.0, 0.0, 0.0])

    def test_incident_reconstructor_ledger_and_bundle(self) -> None:
        """Verifies forensic incident reconstruction and statutory causality analysis."""
        from physical_ai_governor.incident_reconstructor import IncidentReconstructor

        # Seed records into blackbox ledger with an intervention
        pkt_safe = self.ingestor.parse_humanoid_joint_state("r1", 1000, (0, 0, 1), (0, 0, 0), [10], [10], 3.0, 90)
        dec_safe = self.filter.evaluate_safety(pkt_safe)
        self.blackbox.append_record(pkt_safe, dec_safe)

        pkt_hazard = self.ingestor.parse_humanoid_joint_state("r1", 2000, (0, 0, 1), (0, 0, 0), [10], [180], 0.8, 90)
        dec_hazard = self.filter.evaluate_safety(pkt_hazard)
        self.blackbox.append_record(pkt_hazard, dec_hazard)

        report = IncidentReconstructor.reconstruct_from_ledger(self.blackbox, robot_id="r1")
        self.assertEqual(report.robot_id, "r1")
        self.assertGreater(report.interventions_detected, 0)
        self.assertIn("CRITICAL_HUMAN_PROXIMITY_INTRUSION", report.incident_severity)
        self.assertGreater(len(report.causality_tree), 0)
        self.assertGreater(len(report.regulatory_statutory_findings), 0)

    def test_incident_reconstructor_empty_ledger(self) -> None:
        """Verifies incident reconstruction handling of empty black-box ledger."""
        from physical_ai_governor.incident_reconstructor import IncidentReconstructor
        from physical_ai_governor.merkle_blackbox import MerkleBlackBoxLedger

        empty_ledger = MerkleBlackBoxLedger()
        report = IncidentReconstructor.reconstruct_from_ledger(empty_ledger, robot_id="empty_bot")
        self.assertEqual(report.robot_id, "empty_bot")
        self.assertEqual(report.incident_severity, "NONE")
        self.assertEqual(report.total_cycles_analyzed, 0)
        self.assertEqual(report.interventions_detected, 0)

    def test_rbb_verifier_rejects_unsigned_manifest(self) -> None:
        """
        Adversarial audit gap 1 check:
        Verifies that RobotBlackBoxVerifier fails closed in AUTHENTICATED mode
        if the manifest authentication block is stripped or missing.
        """
        import tempfile
        from physical_ai_governor.rbb_recorder import RobotBlackBoxRecorder
        from physical_ai_governor.rbb_verifier import RobotBlackBoxVerifier

        with tempfile.TemporaryDirectory() as tmp_dir:
            bundle_dir = f"{tmp_dir}/unsigned_manifest_bundle"
            recorder = RobotBlackBoxRecorder(robot_id="manifest_strip_bot", tenant_ref="tenant-test")
            recorder.start_run(task="delivery")
            pkt = self.ingestor.parse_humanoid_joint_state(
                robot_id="manifest_strip_bot",
                timestamp_ns=1000,
                base_pos=(0.0, 0.0, 1.0),
                base_vel=(0.0, 0.0, 0.0),
                current_torques=[10.0],
                commanded_torques=[10.0],
                human_proximity=2.5,
                battery=90.0,
            )
            dec = self.filter.evaluate_safety(pkt)
            recorder.record_safety_cycle(pkt, dec)
            recorder.close_run()
            recorder.export_bundle(bundle_dir)

            # Strip authentication from manifest.json
            manifest_path = pathlib.Path(bundle_dir) / "manifest.json"
            manifest = json.loads(manifest_path.read_text())
            manifest.pop("authentication", None)
            manifest_path.write_text(json.dumps(manifest, indent=2))

            report = RobotBlackBoxVerifier.verify_bundle(
                bundle_dir,
                trust_mode="AUTHENTICATED",
                external_trusted_keys=recorder.get_trusted_keys(),
            )
            self.assertFalse(report.is_valid)
            self.assertFalse(report.is_authenticated)
            self.assertTrue(any("MANIFEST_AUTHENTICATION_MISSING" in e for e in report.errors))

    def test_rbb_verifier_rejects_empty_checkpoints_bypass(self) -> None:
        """
        Adversarial audit gap 2 check:
        Verifies that stripping checkpoints (checkpoints.json = []) fails closed
        in AUTHENTICATED mode with WITNESS_EVIDENCE_REQUIRED.
        """
        import tempfile
        from physical_ai_governor.rbb_contract import canonical_json, sha256_hex
        from physical_ai_governor.rbb_recorder import RobotBlackBoxRecorder
        from physical_ai_governor.rbb_verifier import RobotBlackBoxVerifier

        with tempfile.TemporaryDirectory() as tmp_dir:
            bundle_dir = f"{tmp_dir}/empty_checkpoints_bundle"
            recorder = RobotBlackBoxRecorder(robot_id="witness_strip_bot", tenant_ref="tenant-test")
            recorder.start_run(task="patrol")
            pkt = self.ingestor.parse_humanoid_joint_state(
                robot_id="witness_strip_bot",
                timestamp_ns=1000,
                base_pos=(0.0, 0.0, 1.0),
                base_vel=(0.0, 0.0, 0.0),
                current_torques=[10.0],
                commanded_torques=[10.0],
                human_proximity=2.5,
                battery=90.0,
            )
            dec = self.filter.evaluate_safety(pkt)
            recorder.record_safety_cycle(pkt, dec)
            recorder.close_run()
            recorder.export_bundle(bundle_dir)

            # Empty checkpoints.json and update its manifest digest
            checkpoints_path = pathlib.Path(bundle_dir) / "checkpoints.json"
            checkpoints_path.write_text("[]")
            empty_cp_digest = sha256_hex(b"[]")

            manifest_path = pathlib.Path(bundle_dir) / "manifest.json"
            manifest = json.loads(manifest_path.read_text())
            for item in manifest.get("files", []):
                if item.get("path") == "checkpoints.json":
                    item["digest"] = empty_cp_digest
            manifest_path.write_text(json.dumps(manifest, indent=2))

            report = RobotBlackBoxVerifier.verify_bundle(
                bundle_dir,
                trust_mode="AUTHENTICATED",
                external_trusted_keys=recorder.get_trusted_keys(),
            )
            self.assertFalse(report.is_valid)
            self.assertFalse(report.is_authenticated)
            self.assertTrue(any("WITNESS_EVIDENCE_REQUIRED" in e or "WITNESS_DIGEST_MISMATCH" in e for e in report.errors))

    def test_rbb_verifier_validates_and_authenticates_latest_heads(self) -> None:
        """
        Adversarial audit gap 2 check:
        Verifies that latest-heads.json signature is cryptographically verified against
        trusted witnesses and correctly bound to the checkpoint chain.
        """
        import tempfile
        from physical_ai_governor.rbb_recorder import RobotBlackBoxRecorder
        from physical_ai_governor.rbb_verifier import RobotBlackBoxVerifier

        with tempfile.TemporaryDirectory() as tmp_dir:
            bundle_dir = f"{tmp_dir}/latest_heads_bundle"
            recorder = RobotBlackBoxRecorder(robot_id="heads_bot", tenant_ref="tenant-test")
            recorder.start_run(task="surveillance")
            pkt = self.ingestor.parse_humanoid_joint_state(
                robot_id="heads_bot",
                timestamp_ns=1000,
                base_pos=(0.0, 0.0, 1.0),
                base_vel=(0.0, 0.0, 0.0),
                current_torques=[10.0],
                commanded_torques=[10.0],
                human_proximity=2.5,
                battery=90.0,
            )
            dec = self.filter.evaluate_safety(pkt)
            recorder.record_safety_cycle(pkt, dec)
            recorder.close_run()
            recorder.export_bundle(bundle_dir)

            trusted_keys = recorder.get_trusted_keys()
            report = RobotBlackBoxVerifier.verify_bundle(
                bundle_dir,
                trust_mode="AUTHENTICATED",
                external_trusted_keys=trusted_keys,
            )
            self.assertTrue(report.is_valid)
            self.assertTrue(report.is_authenticated)
            self.assertIn("witness_latest_heads_signature_authenticated", report.checks_passed)

            # Tampering with latest-heads signature fails closed
            heads_path = pathlib.Path(bundle_dir) / "witness" / "latest-heads.json"
            heads_data = json.loads(heads_path.read_text())
            run_key = list(heads_data.keys())[0]
            heads_data[run_key]["authentication"]["signature"] = "deadbeef" * 8
            heads_path.write_text(json.dumps(heads_data, indent=2))

            tampered_report = RobotBlackBoxVerifier.verify_bundle(
                bundle_dir,
                trust_mode="AUTHENTICATED",
                external_trusted_keys=trusted_keys,
            )
            self.assertFalse(tampered_report.is_valid)
            self.assertTrue(any("WITNESS_SIGNATURE_INVALID" in e for e in tampered_report.errors))

    def test_blinded_commitment_rejects_fabricated_claims_and_verifies_opening(self) -> None:
        """
        Adversarial audit gap 3 check:
        Verifies that fabricated invariant strings are rejected, and that
        individual cycle compliance is verified via opening proofs.
        """
        import hashlib
        from physical_ai_governor.zk_proof import BlindedSafetyProver

        pkt = self.ingestor.parse_humanoid_joint_state("r1", 1000, (0, 0, 1), (0, 0, 0), [10], [10], 2.5, 90)
        dec = self.filter.evaluate_safety(pkt)
        self.blackbox.append_record(pkt, dec)

        prover = BlindedSafetyProver()
        env = prover.generate_blinded_envelope(self.blackbox, robot_id="r1")
        self.assertTrue(prover.verify_blinded_envelope(env))

        # Fabricated invariant claim must be rejected
        env.invariants_certified = ["I certify anything without constraints"]
        fiat_shamir = f"{env.merkle_root}:{','.join(env.invariants_certified)}:{''.join(env.blinded_commitments)}".encode()
        env.challenge_hash = hashlib.sha256(fiat_shamir).hexdigest()
        self.assertFalse(prover.verify_blinded_envelope(env))

        # Opening proof verification rejects invalid opening
        self.assertFalse(
            prover.verify_opening(
                env,
                cycle_index=0,
                leaf_hash="invalid_leaf",
                is_safe=True,
                human_proximity=2.5,
                blinding_factor="invalid_factor",
            )
        )

    def test_control_barrier_rejects_non_finite_inputs(self) -> None:
        """
        Adversarial audit gap 4 check:
        Verifies that NaN and Inf in telemetry packet (including position_xyz)
        are rejected with INVALID_INPUT and trigger fail-safe protective stop.
        """
        from physical_ai_governor.control_barrier import ControlBarrierFilter, QPSafetyFilter

        cbf = ControlBarrierFilter()
        qp = QPSafetyFilter()

        # NaN in position_xyz
        pkt_nan_pos = self.ingestor.parse_humanoid_joint_state(
            robot_id="nan_pos_bot",
            timestamp_ns=1000,
            base_pos=(float("nan"), 0.0, 1.0),
            base_vel=(0.0, 0.0, 0.0),
            current_torques=[10.0, -10.0],
            commanded_torques=[20.0, -20.0],
            human_proximity=2.0,
            battery=90.0,
        )
        res_cbf = cbf.evaluate_safety(pkt_nan_pos)
        self.assertFalse(res_cbf.is_safe)
        self.assertEqual(res_cbf.decision_status, "INVALID_INPUT")
        self.assertEqual(res_cbf.filtered_command, [0.0, 0.0])

        res_qp = qp.evaluate_safety_qp(pkt_nan_pos)
        self.assertFalse(res_qp.is_safe)
        self.assertEqual(res_qp.decision_status, "INVALID_INPUT")
        self.assertEqual(res_qp.filtered_command, [0.0, 0.0])

        # Inf in command_torque_input
        pkt_inf_torque = self.ingestor.parse_humanoid_joint_state(
            robot_id="inf_bot",
            timestamp_ns=1000,
            base_pos=(0.0, 0.0, 1.0),
            base_vel=(0.0, 0.0, 0.0),
            current_torques=[10.0, -10.0],
            commanded_torques=[float("inf"), 10.0],
            human_proximity=2.0,
            battery=90.0,
        )
        res_inf = cbf.evaluate_safety(pkt_inf_torque)
        self.assertFalse(res_inf.is_safe)
        self.assertEqual(res_inf.decision_status, "INVALID_INPUT")

    def test_cbf_directional_relative_human_approach(self) -> None:
        """
        Adversarial audit gap 4 check:
        Verifies that directional Lie derivative L_f h evaluates approach vs retreat
        with respect to human relative position rather than world origin.
        """
        from physical_ai_governor.control_barrier import QPSafetyFilter

        qp = QPSafetyFilter(min_human_distance_m=1.50)
        control_g = [[-1.0, 0.0]]  # maps u to velocity along relative axis

        # Human is at relative position (1.6, 0.0, 0.0)
        # Case 1: Robot moving AWAY from human (vel = (-1.0, 0.0, 0.0))
        pkt_retreat = self.ingestor.parse_humanoid_joint_state(
            robot_id="retreat_bot",
            timestamp_ns=1000,
            base_pos=(100.0, 200.0, 0.0),  # arbitrary world coords far from origin
            base_vel=(-1.0, 0.0, 0.0),    # retreating away from human
            current_torques=[10.0, 10.0],
            commanded_torques=[10.0, 10.0],
            human_proximity=1.6,
            battery=90.0,
            human_relative_position_xyz=(1.6, 0.0, 0.0),
            human_velocity_xyz=(0.0, 0.0, 0.0),
        )
        dec_retreat = qp.evaluate_safety_qp(pkt_retreat, control_matrix_g=control_g)

        # Case 2: Robot moving TOWARD human (vel = (1.0, 0.0, 0.0))
        pkt_approach = self.ingestor.parse_humanoid_joint_state(
            robot_id="approach_bot",
            timestamp_ns=1000,
            base_pos=(100.0, 200.0, 0.0),  # same world coords
            base_vel=(1.0, 0.0, 0.0),     # approaching human
            current_torques=[10.0, 10.0],
            commanded_torques=[10.0, 10.0],
            human_proximity=1.6,
            battery=90.0,
            human_relative_position_xyz=(1.6, 0.0, 0.0),
            human_velocity_xyz=(0.0, 0.0, 0.0),
        )
        dec_approach = qp.evaluate_safety_qp(pkt_approach, control_matrix_g=control_g)

        # Retreating robot is allowed higher positive command effort than approaching robot
        self.assertGreater(dec_retreat.filtered_command[0], dec_approach.filtered_command[0])

    def test_blinded_commitment_parse_invariants_rejects_non_finite(self) -> None:
        """
        Adversarial audit gap 6 check:
        Verifies that parse_invariant_claim rejects non-finite thresholds ('nan', 'inf')
        and negative or out-of-domain bounds, requiring valid units and finite floats.
        """
        from physical_ai_governor.zk_proof import parse_invariant_claim, validate_invariant_claim

        self.assertFalse(validate_invariant_claim("min_human_distance >= nanm"))
        self.assertFalse(validate_invariant_claim("min_human_distance >= infm"))
        self.assertFalse(validate_invariant_claim("min_human_distance >= -1.5m"))
        self.assertFalse(validate_invariant_claim("max_joint_torque <= nanNm"))
        self.assertFalse(validate_invariant_claim("max_velocity <= 0.0m/s"))

        pred = parse_invariant_claim("min_human_distance >= 1.5m")
        self.assertIsNotNone(pred)
        self.assertEqual(pred.threshold, 1.5)
        self.assertEqual(pred.unit, "m")
        self.assertTrue(validate_invariant_claim("min_human_distance >= 1.5m"))

    def test_blinded_commitment_opening_package_and_predicate_verification(self) -> None:
        """
        Adversarial audit gap 1 & 3 check:
        Verifies that generate_envelope_with_openings produces an exportable opening package,
        and verify_opening_package verifies Merkle inclusion and safety predicates across all cycles.
        """
        from physical_ai_governor.zk_proof import BlindedSafetyProver

        pkt = self.ingestor.parse_humanoid_joint_state("bot_opening", 1000, (0, 0, 1), (0, 0, 0), [10], [10], 2.5, 90)
        dec = self.filter.evaluate_safety(pkt)
        self.blackbox.append_record(pkt, dec)

        prover = BlindedSafetyProver()
        envelope, package = prover.generate_envelope_with_openings(self.blackbox, robot_id="bot_opening")
        self.assertEqual(package.total_cycles, 1)
        self.assertEqual(len(package.openings), 1)

        # Full opening package verification
        status = BlindedSafetyProver.verify_opening_package(envelope, package)
        self.assertTrue(status.is_valid)
        self.assertEqual(status.status, "PREDICATES_VERIFIED")
        self.assertEqual(status.cycles_verified, 1)

    def test_blinded_commitment_rejects_unsafe_opening(self) -> None:
        """
        Adversarial audit gap 2 check:
        Verifies that verify_opening evaluates revealed values against certified safety predicates.
        Revealing an unsafe distance (e.g. 0.1m) for a commitment claiming min_human_distance >= 1.5m
        MUST be rejected even if hash consistency matches.
        """
        import hashlib
        from physical_ai_governor.zk_proof import BlindedSafetyProver, BlindedSafetyEnvelope

        merkle_root = "aa" * 32
        invariants = ["min_human_distance >= 1.5m", "forward_invariance_cbf_simulated == True"]
        r_blind = "11" * 16
        leaf_hash = "bb" * 32

        # Attacker crafts hash matching unsafe distance 0.1m
        unsafe_prox = 0.1
        is_safe = True
        payload = f"{leaf_hash}:{is_safe}:{unsafe_prox}:{r_blind}".encode()
        commit = hashlib.sha256(payload).hexdigest()

        fiat_shamir = f"{merkle_root}:{','.join(invariants)}:{commit}".encode()
        challenge = hashlib.sha256(fiat_shamir).hexdigest()

        resp_input = f"{challenge}:{commit}:{r_blind}:{is_safe}".encode()
        resp = hashlib.sha256(resp_input).hexdigest()

        envelope = BlindedSafetyEnvelope(
            proof_id="unsafe-test",
            robot_id="attacker-bot",
            merkle_root=merkle_root,
            total_cycles_proven=1,
            invariants_certified=invariants,
            challenge_hash=challenge,
            response_proofs=[resp],
            blinded_commitments=[commit],
            timestamp=100.0,
        )

        # verify_opening must reject the unsafe distance despite valid hash commitment
        res = BlindedSafetyProver.verify_opening(
            envelope=envelope,
            cycle_index=0,
            leaf_hash=leaf_hash,
            is_safe=is_safe,
            human_proximity=unsafe_prox,
            blinding_factor=r_blind,
        )
        self.assertFalse(res)

    def test_blinded_commitment_rejects_invalid_merkle_proof(self) -> None:
        """
        Adversarial audit gap 2 check:
        Verifies that verify_opening rejects an opening when the Merkle inclusion proof is invalid.
        """
        from physical_ai_governor.zk_proof import BlindedSafetyProver

        pkt = self.ingestor.parse_humanoid_joint_state("bot_mp", 1000, (0, 0, 1), (0, 0, 0), [10], [10], 2.5, 90)
        dec = self.filter.evaluate_safety(pkt)
        self.blackbox.append_record(pkt, dec)

        prover = BlindedSafetyProver()
        envelope, package = prover.generate_envelope_with_openings(self.blackbox, robot_id="bot_mp")
        op0 = package.openings[0]

        # Corrupted Merkle proof
        fake_merkle_proof = [("deadbeef" * 8, "left")]
        res = BlindedSafetyProver.verify_opening(
            envelope=envelope,
            cycle_index=0,
            leaf_hash=op0.leaf_hash,
            is_safe=op0.is_safe,
            human_proximity=op0.human_proximity,
            blinding_factor=op0.blinding_factor,
            merkle_proof=fake_merkle_proof,
        )
        self.assertFalse(res)

    def test_control_barrier_rejects_conflicting_distance_measurements(self) -> None:
        """
        Adversarial audit gap 4 check:
        Verifies that when scalar human_distance_meters and norm(human_relative_position_xyz)
        disagree beyond sensor uncertainty, both CBF and QP-CBF reject the packet with
        INVALID_INPUT and engage a fail-safe protective stop.
        """
        from physical_ai_governor.control_barrier import ControlBarrierFilter, QPSafetyFilter

        cbf = ControlBarrierFilter()
        qp = QPSafetyFilter()

        # Conflicting distance: scalar says 3.0m, but relative position vector norm is 0.1m
        pkt_conflict = self.ingestor.parse_humanoid_joint_state(
            robot_id="conflict_bot",
            timestamp_ns=1000,
            base_pos=(0.0, 0.0, 1.0),
            base_vel=(0.0, 0.0, 0.0),
            current_torques=[10.0, 10.0],
            commanded_torques=[10.0, 10.0],
            human_proximity=3.0,
            battery=90.0,
            human_relative_position_xyz=(0.1, 0.0, 0.0),  # norm = 0.1m, diff = 2.9m >> 0.50m
            human_velocity_xyz=(0.0, 0.0, 0.0),
        )

        res_cbf = cbf.evaluate_safety(pkt_conflict)
        self.assertFalse(res_cbf.is_safe)
        self.assertEqual(res_cbf.decision_status, "INVALID_INPUT")
        self.assertIn("SENSOR_DISCREPANCY", res_cbf.violation_reason)
        self.assertEqual(res_cbf.filtered_command, [0.0, 0.0])

        res_qp = qp.evaluate_safety_qp(pkt_conflict)
        self.assertFalse(res_qp.is_safe)
        self.assertEqual(res_qp.decision_status, "INVALID_INPUT")
        self.assertIn("SENSOR_DISCREPANCY", res_qp.violation_reason)
        self.assertEqual(res_qp.filtered_command, [0.0, 0.0])

    def test_rbb_verifier_rejects_algorithm_confusion(self) -> None:
        """
        Adversarial audit gap 5 check:
        Verifies that relabeling authentication algorithm from 'sha256-hmac' to 'ed25519'
        is detected and fails closed with ALGORITHM_MISMATCH.
        """
        import tempfile
        from physical_ai_governor.rbb_recorder import RobotBlackBoxRecorder
        from physical_ai_governor.rbb_verifier import RobotBlackBoxVerifier

        with tempfile.TemporaryDirectory() as tmp_dir:
            bundle_dir = f"{tmp_dir}/algo_confusion_bundle"
            recorder = RobotBlackBoxRecorder(robot_id="algo_bot", tenant_ref="tenant-test")
            recorder.start_run(task="security_check")
            pkt = self.ingestor.parse_humanoid_joint_state(
                robot_id="algo_bot",
                timestamp_ns=1000,
                base_pos=(0.0, 0.0, 1.0),
                base_vel=(0.0, 0.0, 0.0),
                current_torques=[10.0],
                commanded_torques=[10.0],
                human_proximity=2.5,
                battery=90.0,
            )
            dec = self.filter.evaluate_safety(pkt)
            recorder.record_safety_cycle(pkt, dec)
            recorder.close_run()
            recorder.export_bundle(bundle_dir)

            # Change manifest authentication algorithm to ed25519
            manifest_path = pathlib.Path(bundle_dir) / "manifest.json"
            manifest = json.loads(manifest_path.read_text())
            manifest["authentication"]["algorithm"] = "ed25519"
            manifest_path.write_text(json.dumps(manifest, indent=2))

            report = RobotBlackBoxVerifier.verify_bundle(
                bundle_dir,
                trust_mode="AUTHENTICATED",
                external_trusted_keys=recorder.get_trusted_keys(),
            )
            self.assertFalse(report.is_valid)
            self.assertFalse(report.is_authenticated)
            self.assertTrue(any("ALGORITHM_MISMATCH" in e for e in report.errors))


if __name__ == "__main__":
    unittest.main()
