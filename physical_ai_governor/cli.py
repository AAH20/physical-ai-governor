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


def cmd_grc_claw_sync(args: argparse.Namespace) -> int:
    """Synchronizes notarized compliance passport with GRC_Claw evidence plane."""
    from .grc_claw_bridge import GRCClawBridge

    print(f"🦞 Synchronizing with GRC_Claw Gateway ({args.gateway_url})...")
    ingestor = TelemetryIngestor()
    cbf = ControlBarrierFilter()
    ledger = MerkleBlackBoxLedger()

    for i in range(args.cycles):
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
    bridge = GRCClawBridge(gateway_url=args.gateway_url, tenant_id=args.tenant_id)
    evidence = bridge.build_evidence_record(passport)
    iso42001 = bridge.assess_iso42001_readiness(passport)
    sync_result = bridge.sync_to_gateway(evidence)

    print("=" * 65)
    print("  GRC_CLAW (ISO 42001) EVIDENCE SYNCHRONIZATION")
    print("=" * 65)
    print(f"  Robot ID:                    {passport.robot_id}")
    print(f"  Evidence URI:                {evidence.uri}")
    print(f"  Canonical SHA256:            {evidence.sha256}")
    print(f"  Control ID:                  {evidence.controlId}")
    print(f"  ISO 42001 Readiness:        {iso42001['overall_iso42001_readiness']}")
    print(f"  Gateway Sync Status:         {sync_result['status']}")
    if "message" in sync_result:
        print(f"  Gateway Note:                {sync_result['message']}")
    print("=" * 65)

    if args.output:
        bundle = {
            "evidence": evidence.to_dict(),
            "iso42001_assessment": iso42001,
            "sync_result": sync_result,
        }
        with open(args.output, "w", encoding="utf-8") as f:
            f.write(json.dumps(bundle, indent=2))
        print(f"✅ GRC_Claw evidence bundle saved to: {args.output}")

    return 0


def cmd_zk_prove(args: argparse.Namespace) -> int:
    """Generates a verifiable Zero-Knowledge (ZK) safety proof over flight logs."""
    from .zk_proof import ZKSafetyProver

    print(f"🛡️ Generating Zero-Knowledge Safety Invariance Proof ({args.cycles} cycles)...")
    ingestor = TelemetryIngestor()
    cbf = ControlBarrierFilter()
    ledger = MerkleBlackBoxLedger()

    for i in range(args.cycles):
        pkt = ingestor.parse_humanoid_joint_state(
            robot_id=args.robot_id,
            timestamp_ns=i * 1_000_000,
            base_pos=(0.0, 0.0, 1.2),
            base_vel=(0.2, 0.0, 0.0),
            current_torques=[30.0, -20.0],
            commanded_torques=[40.0, -30.0],
            human_proximity=2.5,
            battery=90.0,
        )
        dec = cbf.evaluate_safety(pkt)
        ledger.append_record(pkt, dec)

    prover = ZKSafetyProver()
    envelope = prover.generate_zk_proof(ledger, robot_id=args.robot_id)
    is_valid = ZKSafetyProver.verify_zk_proof(envelope)

    print("=" * 65)
    print("  BLINDED COMMITMENT SAFETY ENVELOPE (PRIVACY AUDIT)")
    print("=" * 65)
    print(f"  Proof ID:                    {envelope.proof_id}")
    print(f"  Robot ID:                    {envelope.robot_id}")
    print(f"  Merkle Root Anchor:          {envelope.merkle_root}")
    print(f"  Cycles Proven:               {envelope.total_cycles_proven}")
    print(f"  Fiat-Shamir Challenge:       {envelope.challenge_hash[:20]}...")
    print(f"  Blinded Envelope Verified:   {is_valid}")
    print("  Invariants Claimed (Zero Coordinate Leakage):")
    for inv in envelope.invariants_certified:
        print(f"    • {inv}")
    print("=" * 65)

    if args.output:
        with open(args.output, "w", encoding="utf-8") as f:
            f.write(json.dumps(envelope.to_dict(), indent=2))
        print(f"✅ Blinded safety envelope saved to: {args.output}")

    return 0


def cmd_swarm_eval(args: argparse.Namespace) -> int:
    """Simulates reciprocal multi-robot / swarm collision avoidance."""
    from .swarm_cbf import SwarmAgentState, SwarmControlBarrierGovernor

    print(f"🐝 Simulating Reciprocal Multi-Agent CBF Collision Avoidance ({args.agents} agents)...")
    gov = SwarmControlBarrierGovernor(min_inter_agent_distance_m=2.0)

    # Initialize agents on converging paths
    agents = [
        SwarmAgentState("drone_alpha", (0.0, 0.0, 10.0), (1.5, 0.0, 0.0), (1.5, 0.0, 0.0)),
        SwarmAgentState("drone_bravo", (1.8, 0.0, 10.0), (-1.5, 0.0, 0.0), (-1.5, 0.0, 0.0)),
    ]
    if args.agents > 2:
        agents.append(SwarmAgentState("drone_charlie", (0.9, 1.2, 10.0), (0.0, -1.0, 0.0), (0.0, -1.0, 0.0)))

    decisions = gov.evaluate_swarm_safety(agents)

    print("=" * 65)
    print("  SWARM-CBF COLLISION AVOIDANCE REPORT")
    print("=" * 65)
    for agent_id, dec in decisions.items():
        status = "SAFE_PASS" if dec.is_safe else "CBF_RECIPROCAL_INTERVENTION"
        print(f"  [{agent_id}] -> {status}")
        print(f"    • Filtered Velocity:   {dec.filtered_velocity}")
        print(f"    • Min Distance:        {dec.min_inter_agent_distance_m} m")
        if dec.threat_agent_ids:
            print(f"    • Collision Threats:   {', '.join(dec.threat_agent_ids)}")
    print("=" * 65)
    return 0


def cmd_rbb_record(args: argparse.Namespace) -> int:
    """Records real-time physical AI telemetry into an RBB bundle."""
    from .rbb_recorder import RobotBlackBoxRecorder

    print(f"📼 Recording Physical AI Black Box flight log ({args.cycles} cycles)...")
    ingestor = TelemetryIngestor()
    cbf = ControlBarrierFilter()
    recorder = RobotBlackBoxRecorder(robot_id=args.robot_id, tenant_ref=args.tenant_ref)
    recorder.start_run(task="benign_block_handover")

    for i in range(args.cycles):
        cmd_torque = [40.0, -30.0] if (i % 7 != 0) else [180.0, -210.0]
        dist = 2.5 if (i % 5 != 0) else 1.2
        pkt = ingestor.parse_humanoid_joint_state(
            robot_id=args.robot_id,
            timestamp_ns=i * 1_000_000,
            base_pos=(0.0, 0.0, 1.2),
            base_vel=(0.2, 0.0, 0.0),
            current_torques=[30.0, -20.0],
            commanded_torques=cmd_torque,
            human_proximity=dist,
            battery=95.0 - (i * 0.01),
        )
        dec = cbf.evaluate_safety(pkt)
        recorder.record_safety_cycle(pkt, dec)

    recorder.close_run()
    result = recorder.export_bundle(args.out)

    print("=" * 65)
    print("  ROBOT BLACK BOX (RBB) BUNDLE RECORDED")
    print("=" * 65)
    print(f"  Run ID:                      {result['run_id']}")
    print(f"  Bundle Directory:            {result['bundle_path']}")
    print(f"  Total Events:                {result['total_events']}")
    print(f"  Head Digest:                 {result['head_digest'][:16]}...")
    print(f"  Events Digest:               {result['events_digest'][:16]}...")
    print(f"  Checkpoints Digest:          {result['checkpoints_digest'][:16]}...")
    print("=" * 65)
    return 0


def cmd_rbb_verify(args: argparse.Namespace) -> int:
    """Audits and cryptographically verifies an on-disk RBB bundle."""
    from .rbb_verifier import RobotBlackBoxVerifier

    print(f"🔍 Verifying Robot Black Box bundle at: {args.bundle}")
    report = RobotBlackBoxVerifier.verify_bundle(args.bundle)

    if args.json:
        print(json.dumps(report.to_dict(), indent=2))
    else:
        print("=" * 65)
        print("  ROBOT BLACK BOX (RBB) BUNDLE AUDIT REPORT")
        print("=" * 65)
        print(f"  Bundle Status:               {'VALID (PASSED)' if report.is_valid else 'INVALID (FAILED)'}")
        print(f"  Run ID:                      {report.run_id}")
        print(f"  Events Verified:             {report.total_events}")
        print(f"  Checkpoints Verified:        {report.total_checkpoints}")
        print(f"  Head Digest:                 {report.head_digest[:16]}...")
        print(f"  Events Digest:               {report.events_digest[:16]}...")
        print("  Checks Passed:")
        for chk in report.checks_passed:
            print(f"    • {chk}")
        if report.errors:
            print("  Errors Detected:")
            for err in report.errors:
                print(f"    ❌ {err}")
        print("=" * 65)
    return 0 if report.is_valid else 2


def cmd_incident_report(args: argparse.Namespace) -> int:
    """Reconstructs and analyzes post-market incidents from RBB bundles or ledgers."""
    from .incident_reconstructor import IncidentReconstructor

    print(f"📋 Generating Forensic Flight Incident Report for: {args.bundle}")
    report = IncidentReconstructor.reconstruct_from_rbb_bundle(args.bundle)

    if args.json:
        print(json.dumps(report.to_dict(), indent=2))
    else:
        print("=" * 65)
        print("  FORENSIC FLIGHT INCIDENT & CAUSALITY REPORT")
        print("=" * 65)
        print(f"  Report ID:                   {report.report_id}")
        print(f"  Robot / Run ID:              {report.robot_id}")
        print(f"  Incident Severity:           {report.incident_severity}")
        print(f"  Total Cycles Analyzed:       {report.total_cycles_analyzed}")
        print(f"  Interventions Detected:      {report.interventions_detected}")
        print(f"  Min Human Proximity:         {report.min_human_distance_recorded_m} m")
        print(f"  Primary Root Cause:          {report.primary_root_cause}")
        print("  Causality Timeline:")
        for cause in report.causality_tree[:5]:
            print(f"    • {cause}")
        print("  Regulatory Statutory Findings:")
        for find in report.regulatory_statutory_findings:
            print(f"    ⚖️  {find}")
        print("=" * 65)

    if args.output:
        with open(args.output, "w", encoding="utf-8") as f:
            f.write(json.dumps(report.to_dict(), indent=2))
        print(f"✅ Forensic report saved to: {args.output}")
    return 0


def cmd_kinodynamics_eval(args: argparse.Namespace) -> int:
    """Evaluates humanoid whole-body self-collision and manipulability barriers."""
    from .whole_body_kinodynamics import WholeBodyKinodynamicsGovernor

    print(f"🦾 Evaluating Humanoid Whole-Body Kinodynamics & Singularity Barriers...")
    gov = WholeBodyKinodynamicsGovernor(min_manipulability=args.min_manip, min_self_collision_distance_m=0.12)

    link_positions = {
        "left_hand": (0.20, 0.15, 0.95),
        "right_hand": (0.22, -0.15, 0.95),
        "torso": (0.0, 0.0, 0.90),
        "left_foot": (0.0, 0.12, 0.0),
        "right_foot": (0.0, -0.12, 0.0),
    }
    joint_angles = [args.joint1, args.joint2, args.joint3]
    cmd_vels = [1.2, -0.8, 0.5]

    state = gov.evaluate_whole_body_safety(link_positions, joint_angles, cmd_vels)

    print("=" * 65)
    print("  WHOLE-BODY KINODYNAMICS & SINGULARITY STATUS")
    print("=" * 65)
    print(f"  State Feasible:              {state.is_safe}")
    print(f"  Yoshikawa Manipulability:    {state.manipulability_index} (min: {state.min_allowed_manipulability})")
    print(f"  Min Self-Distance:           {state.min_self_distance_m} m")
    print(f"  Self-Collision Margin:       {state.self_collision_margin_m} m")
    print(f"  Commanded Velocities:        {cmd_vels}")
    print(f"  Safe Filtered Velocities:    {state.filtered_joint_velocities}")
    if state.interventions:
        print("  Active Interventions:")
        for intv in state.interventions:
            print(f"    ⚠️  {intv}")
    print("=" * 65)
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

    # grc-claw-sync
    p_claw = subparsers.add_parser("grc-claw-sync", help="Synchronize compliance passport with GRC_Claw evidence plane")
    p_claw.add_argument("--gateway-url", type=str, default="http://127.0.0.1:18791", help="GRC_Claw gateway URL")
    p_claw.add_argument("--robot-id", type=str, default="humanoid_gr00t_01", help="Robot identifier")
    p_claw.add_argument("--tenant-id", type=int, default=1, help="GRC_Claw tenant ID")
    p_claw.add_argument("--cycles", type=int, default=100, help="Telemetry cycles to audit")
    p_claw.add_argument("--output", "-o", type=str, default=None, help="Output bundle file path")
    p_claw.set_defaults(func=cmd_grc_claw_sync)

    # rbb-record
    p_rec = subparsers.add_parser("rbb-record", help="Record physical AI telemetry into an RBB bundle")
    p_rec.add_argument("--robot-id", type=str, default="humanoid_gr00t_01", help="Robot identifier")
    p_rec.add_argument("--tenant-ref", type=str, default="tenant-factory-a", help="Tenant reference")
    p_rec.add_argument("--cycles", type=int, default=20, help="Number of telemetry cycles")
    p_rec.add_argument("--out", "-o", type=str, required=True, help="Output directory for RBB bundle")
    p_rec.set_defaults(func=cmd_rbb_record)

    # rbb-verify
    p_ver = subparsers.add_parser("rbb-verify", help="Audit and verify an on-disk RBB bundle")
    p_ver.add_argument("--bundle", "-b", type=str, required=True, help="Path to RBB bundle directory")
    p_ver.add_argument("--json", action="store_true", help="Output verification report in raw JSON")
    p_ver.set_defaults(func=cmd_rbb_verify)

    # incident-report
    p_inc = subparsers.add_parser("incident-report", help="Forensic flight incident reconstruction report")
    p_inc.add_argument("--bundle", "-b", type=str, required=True, help="Path to RBB bundle directory")
    p_inc.add_argument("--output", "-o", type=str, default=None, help="Output JSON path")
    p_inc.add_argument("--json", action="store_true", help="Output raw JSON")
    p_inc.set_defaults(func=cmd_incident_report)

    # kinodynamics-eval
    p_kino = subparsers.add_parser("kinodynamics-eval", help="Evaluate humanoid whole-body kinodynamics")
    p_kino.add_argument("--min-manip", type=float, default=0.05, help="Minimum Yoshikawa manipulability")
    p_kino.add_argument("--joint1", type=float, default=0.5, help="Joint 1 angle (rad)")
    p_kino.add_argument("--joint2", type=float, default=0.4, help="Joint 2 angle (rad)")
    p_kino.add_argument("--joint3", type=float, default=-0.3, help="Joint 3 angle (rad)")
    p_kino.set_defaults(func=cmd_kinodynamics_eval)

    # zk-prove
    p_zk = subparsers.add_parser("zk-prove", help="Generate Zero-Knowledge safety invariance proof")
    p_zk.add_argument("--robot-id", type=str, default="humanoid_defense_01", help="Robot identifier")
    p_zk.add_argument("--cycles", type=int, default=50, help="Telemetry cycles to prove")
    p_zk.add_argument("--output", "-o", type=str, default=None, help="Output file path")
    p_zk.set_defaults(func=cmd_zk_prove)

    # swarm-eval
    p_swarm = subparsers.add_parser("swarm-eval", help="Simulate multi-agent swarm reciprocal CBF")
    p_swarm.add_argument("--agents", type=int, default=3, help="Number of interacting agents")
    p_swarm.set_defaults(func=cmd_swarm_eval)

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
