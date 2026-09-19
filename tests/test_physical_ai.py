"""
Unit test suite for Physical AI Governor.
Pure Python 3.10+ standard library.
"""

import unittest

from physical_ai_governor.control_barrier import ControlBarrierFilter
from physical_ai_governor.evaluator import PhysicalAIBenchmarkRunner
from physical_ai_governor.merkle_blackbox import MerkleBlackBoxLedger
from physical_ai_governor.telemetry_ingest import TelemetryIngestor


class TestPhysicalAIGovernor(unittest.TestCase):
    """Rigorous verification of streaming physical AI telemetry, CBF safety filters, and Merkle black-box."""

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
        pkt = self.ingestor.parse_humanoid_joint_state("r1", 100, (0,0,1), (0,0,0), [10], [10], 2.0, 90)
        dec = self.filter.evaluate_safety(pkt)

        self.blackbox.append_record(pkt, dec)
        self.blackbox.append_record(pkt, dec)
        root = self.blackbox.build_merkle_root()

        self.assertEqual(len(root), 64)
        self.assertEqual(len(self.blackbox.leaf_hashes), 2)

    def test_compliance_passport_issuance(self) -> None:
        """Verifies statutory compliance passport fields and signature."""
        pkt = self.ingestor.parse_humanoid_joint_state("r1", 100, (0,0,1), (0,0,0), [10], [10], 2.0, 90)
        dec = self.filter.evaluate_safety(pkt)
        self.blackbox.append_record(pkt, dec)

        passport = self.blackbox.issue_compliance_passport("humanoid_01", total_interventions=0)
        self.assertEqual(passport.robot_id, "humanoid_01")
        self.assertEqual(passport.faa_part89_remote_id_status, "CERTIFIED_COMPLIANT")
        self.assertEqual(passport.eu_ai_act_annex_iii_status, "SAFETY_COMPONENT_VERIFIED")
        self.assertEqual(len(passport.notary_signature), 64)

    def test_end_to_end_benchmark_runner(self) -> None:
        """Verifies 1000-cycle simulation throughput and zero unmitigated violations."""
        res = self.runner.run_benchmark(num_cycles=1000)
        self.assertEqual(res["total_telemetry_cycles"], 1000)
        self.assertGreater(res["cbf_safety_interventions"], 40)
        self.assertEqual(res["unmitigated_violations"], 0)
        self.assertEqual(res["safety_enforcement_rate"], 1.0)
        self.assertGreater(res["ingestion_throughput_pps"], 15_000.0)
        self.assertLess(res["benchmark_latency_ms"], 100.0)


if __name__ == "__main__":
    unittest.main()
