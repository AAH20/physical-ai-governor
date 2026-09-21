"""
Command-Line Interface (CLI) for Physical AI Governor.
Provides unified commands for:
    - Running high-frequency benchmark stress tests
    - Verifying statutory compliance passports and Merkle inclusion proofs
    - Simulating VLA action chunk horizon safety
    - Exporting EU AI Act Annex III conformity dossiers
"""

import argparse
import json
import sys
from typing import List, Optional

from .control_barrier import ControlBarrierFilter, QPSafetyFilter
from .evaluator import PhysicalAIBenchmarkRunner
from .merkle_blackbox import CompliancePassport, MerkleBlackBoxLedger
from .statutory_engine import StatutoryAssuranceEngine
from .telemetry_ingest import RobotTelemetryPacket, TelemetryIngestor
from .vla_validator import VLAActionHorizonValidator


def cmd_benchmark(args: argparse.Namespace) -> int:
    """Runs high-frequency physical safety benchmark."""
    print(f"🚀 Running Physical AI Governor Benchmark ({args.cycles} cycles)...")
    runner = PhysicalAIBenchmarkRunner()
    results = runner.run_benchmark(num_cycles=args.cycles)

    if args.json:
        print(json.dumps(results, indent=2))
    else:
        print("=" * 60)
        print("  PHYSICAL AI GOVERNOR BENCHMARK RESULTS")
        print("=" * 60)
        print(f"  Total Telemetry Cycles:      {results['total_telemetry_cycles']:,}")
        print(f"  Adversarial Injections:      {results['adversarial_injections']:,}")
        print(f"  CBF Safety Interventions:    {results['cbf_safety_interventions']:,}")
        print(f"  Unmitigated Violations:      {results['unmitigated_violations']}")
        print(f"  Safety Enforcement Rate:     {results['safety_enforcement_rate'] * 100:.2f}%")
        print(f"  Ingestion Throughput:        {results['ingestion_throughput_pps']:,} packets/sec")
        print(f"  Benchmark Elapsed Time:      {results['benchmark_latency_ms']} ms")
        print(f"  Merkle Root:                 {results['merkle_root_hash']}")
        print(f"  Notary Signature:            {results['passport_notary_signature']}")
        print(f"  FAA Part 89 Status:          {results['faa_part89_status']}")
        print(f"  EU AI Act Annex III Status:  {results['eu_ai_act_status']}")
        print("=" * 60)
    return 0


def cmd_vla_eval(args: argparse.Namespace) -> int:
    """Simulates VLA action chunk horizon safety screening."""
    print(f"🤖 Simulating VLA Action Horizon Validation (H={args.horizon} steps)...")
    validator = VLAActionHorizonValidator(
        min_human_distance_m=1.50,
        max_joint_torque_nm=150.0,
    )

    init_pkt = RobotTelemetryPacket(
        robot_id=args.robot_id,
        robot_type="humanoid_biped",
        timestamp_ns=1700000000000,
        position_xyz=(0.0, 0.0, 1.2),
        velocity_xyz=(0.2, 0.0, 0.0),
        joint_torques=[40.0, -30.0],
        human_distance_meters=args.human_dist,
        battery_percentage=92.0,
        command_torque_input=[40.0, -30.0],
    )

    # Generate test action chunk
    action_chunk = [[45.0, -35.0] for _ in range(args.horizon)]
    if args.inject_fault and args.horizon > 2:
        action_chunk[args.horizon // 2] = [210.0, -220.0]  # Exceeds 150 Nm limit

    result = validator.validate_and_filter_chunk(init_pkt, action_chunk)

    print("=" * 60)
    print("  VLA CHUNK HORIZON SAFETY REPORT")
    print("=" * 60)
    print(f"  Chunk Safe:                  {result.is_chunk_safe}")
    print(f"  Horizon Steps Screened:      {result.horizon_steps}")
    print(f"  First Violation Step:        {result.first_violation_step}")
    print(f"  Min Predicted CBF Margin:    {result.min_predicted_cbf_margin:.3f} m")
    if result.violation_reasons:
        print("  Violations Detected:")
        for r in result.violation_reasons:
            print(f"    • {r}")
    print("=" * 60)
    return 0


def cmd_export_dossier(args: argparse.Namespace) -> int:
    """Generates an EU AI Act Annex III technical conformity dossier."""
    ingestor = TelemetryIngestor()
    cbf = ControlBarrierFilter()
    ledger = MerkleBlackBoxLedger()
    statutory = StatutoryAssuranceEngine()

    for i in range(100):
        pkt = ingestor.parse_humanoid_joint_state(
            robot_id=args.robot_id,
            timestamp_ns=i * 1_000_000,
            base_pos=(0, 0, 1.2),
            base_vel=(0.2, 0, 0),
            current_torques=[30, -20],
            commanded_torques=[40, -30],
            human_proximity=2.5,
            battery=90.0,
        )
        dec = cbf.evaluate_safety(pkt)
        ledger.append_record(pkt, dec)

    passport = ledger.issue_compliance_passport(args.robot_id, total_interventions=0)
    dossier = statutory.generate_eu_ai_act_annex_iii_dossier(passport)

    out_str = json.dumps(dossier, indent=2)
    if args.output:
        with open(args.output, "w", encoding="utf-8") as f:
            f.write(out_str)
        print(f"✅ EU AI Act Annex III Dossier written to: {args.output}")
    else:
        print(out_str)
    return 0


def cmd_remote_id(args: argparse.Namespace) -> int:
    """Generates an ASTM F3411-22a / FAA Part 89 broadcast payload."""
    engine = StatutoryAssuranceEngine()
    rid = engine.synthesize_faa_part89_remote_id(
        lat=args.lat,
        lon=args.lon,
        alt_m=args.alt,
        speed_mps=args.speed,
        operator_id=args.operator_id,
    )
    print(json.dumps(rid, indent=2))
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="physical-ai-governor",
        description="Autonomous Physical AI, Humanoid (GR00T) & Drone Swarm GRC Assurance Engine",
    )
    subparsers = parser.add_subparsers(dest="command", help="Available commands")

    # benchmark
    p_bench = subparsers.add_parser("benchmark", help="Run high-frequency CBF benchmark")
    p_bench.add_argument("--cycles", type=int, default=1000, help="Number of telemetry cycles (default: 1000)")
    p_bench.add_argument("--json", action="store_true", help="Output results in raw JSON")
    p_bench.set_defaults(func=cmd_benchmark)

    # vla-eval
    p_vla = subparsers.add_parser("vla-eval", help="Simulate VLA action chunk horizon validation")
    p_vla.add_argument("--horizon", type=int, default=8, help="Action horizon length (default: 8)")
    p_vla.add_argument("--robot-id", type=str, default="humanoid_unitree_h1", help="Robot ID")
    p_vla.add_argument("--human-dist", type=float, default=2.0, help="Human distance in meters")
    p_vla.add_argument("--inject-fault", action="store_true", default=True, help="Inject hazardous torque in middle step")
    p_vla.set_defaults(func=cmd_vla_eval)

    # export-dossier
    p_dossier = subparsers.add_parser("export-dossier", help="Export EU AI Act Annex III technical dossier")
    p_dossier.add_argument("--robot-id", type=str, default="humanoid_gr00t_01", help="Robot ID")
    p_dossier.add_argument("--output", "-o", type=str, default=None, help="Output file path (default: stdout)")
    p_dossier.set_defaults(func=cmd_export_dossier)

    # remote-id
    p_rid = subparsers.add_parser("remote-id", help="Synthesize FAA Part 89 Remote ID broadcast packet")
    p_rid.add_argument("--lat", type=float, default=37.7749, help="Latitude (deg)")
    p_rid.add_argument("--lon", type=float, default=-122.4194, help="Longitude (deg)")
    p_rid.add_argument("--alt", type=float, default=120.0, help="Altitude MSL (meters)")
    p_rid.add_argument("--speed", type=float, default=5.0, help="Horizontal speed (m/s)")
    p_rid.add_argument("--operator-id", type=str, default="FAA-US-2026-PHYSICAL-AI", help="Registered Operator ID")
    p_rid.set_defaults(func=cmd_remote_id)

    return parser


def main(argv: Optional[List[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if not hasattr(args, "func"):
        parser.print_help()
        return 1
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
