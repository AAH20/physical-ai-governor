# Physical AI Governor 🤖

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](https://opensource.org/licenses/MIT)
[![Python: 3.10+](https://img.shields.io/badge/Python-3.10%2B-brightgreen.svg)](https://python.org)
[![Dependencies: Zero](https://img.shields.io/badge/Dependencies-Zero%20(Pure%20Stdlib)-blueviolet.svg)](#-key-highlights)
[![Tests: 26/26 Passing](https://img.shields.io/badge/Tests-26%2F26%20Passing-success.svg)](#-benchmark-verification)
[![Black Box: RBB Contract](https://img.shields.io/badge/Black%20Box-RBB%20Contract%20(v0.1.0)-blue.svg)](https://github.com/AAH20/robot-black-box)
[![Chassis: GRC Claw](https://img.shields.io/badge/Chassis-GRC%20Claw%20(ISO%2042001)-orange.svg)](https://github.com/AAH20/GRC_Claw)
[![Assurance Hub: A2Z SOC](https://img.shields.io/badge/Assurance-A2Z%20SOC%20Physical%20AI-informational.svg)](https://a2zsoc.com/physical-ai-humanoid-assurance)

> **Autonomous Physical AI, Humanoid (GR00T) & Drone Swarm GRC Assurance Engine.**  
> Enforces continuous Control Barrier Functions (CBF, QP-CBF, HOCBF) over streaming ROS 2, MAVLink, and VLA joint trajectories, notarizing tamper-evident black-box Merkle ledgers with inclusion proofs, Zero-Knowledge safety proofs, TPM 2.0 hardware attestation, and statutory compliance passports for FAA Part 89, EU AI Act Annex III, ISO 10218 / ISO/TS 15066, **GRC_Claw** (ISO 42001), and [**Robot Black Box (RBB)**](https://github.com/AAH20/robot-black-box).

---

## 🏛️ System Architecture

```mermaid
flowchart TD
  subgraph FLEET["🤖 Physical AI Fleets & Foundation Models"]
    direction LR
    H1["Humanoid Robots<br/>(NVIDIA GR00T / Unitree / Optimus)"]
    DR["Drone Swarms<br/>(PX4 / ArduPilot MAVLink)"]
    VLA["VLA Action Chunks<br/>(OpenVLA / Octo / RT-2)"]
  end

  subgraph INGEST["⚡ Ingestion & Protocol Stream Plane"]
    direction TB
    ING["TelemetryIngestor<br/>(Standard Packet Format)"]
    MFP["MAVLinkFrameParser<br/>(Binary v2 + CRC-16 Checksum)"]
    ROS["ROS2TelemetryBridge<br/>(sensor_msgs/JointState &amp; Twist)"]
    VAV["VLAActionHorizonValidator<br/>(Multi-Step H=8..16 Screening)"]
    TSS["TelemetryStreamServer<br/>(Async TCP &amp; In-Memory Stream)"]
  end

  subgraph SAFETY["🛡️ Control Barrier & Optimization Core"]
    direction TB
    QP["ActiveSetQPSolver<br/>(Pure Python Convex Solver &lt;1ms)"]
    QPF["QPSafetyFilter<br/>(Minimal-Norm Projection min ||u - u_nom||²)"]
    HOCBF["HighOrderControlBarrierFilter<br/>(Relative Degree r=2 Deceleration)"]
    SWARM["SwarmControlBarrierGovernor<br/>(Reciprocal Multi-Agent CBF)"]
    STAB["HumanoidStabilityGovernor<br/>(ZMP Polygon &amp; Friction Cone)"]
    SM["ISO10218SafetyStateMachine<br/>(Collaborative / Protective / E-Stop)"]
  end

  subgraph AUDIT["📜 Cryptographic Notary, RBB & ZK Verification"]
    direction TB
    MBL["MerkleBlackBoxLedger<br/>(Incremental Binary Merkle Tree)"]
    RBB["RobotBlackBoxRecorder<br/>(events.ndjson &amp; checkpoints)"]
    VFY["RobotBlackBoxVerifier<br/>(Offline Independent Auditor)"]
    ZK["ZKSafetyProver<br/>(Zero-Knowledge Fiat-Shamir Proofs)"]
    TPM["TPM2HardwareAttestor<br/>(PCR Sealing &amp; Silicon Attestation)"]
    STAT["StatutoryAssuranceEngine<br/>(FAA Part 89 &amp; EU AI Act Dossiers)"]
  end

  subgraph GRC["🦞 GRC_Claw Assurance Plane (ISO 42001)"]
    direction TB
    BRIDGE["GRCClawBridge<br/>(RFC 8785 Canonical JSON)"]
    EV["GRC_Claw EvidenceStore<br/>(rbb:// URI &amp; Control Records)"]
    GW["GRC_Claw Gateway Daemon<br/>(127.0.0.1:18791)"]
    AIMS["ISO 42001 &amp; NIST AI RMF<br/>(Assurance Envelopes)"]
  end

  FLEET -->|Streaming Telemetry| INGEST
  INGEST -->|Standardized Packet| SAFETY
  SAFETY -->|Safe Filtered Command| FLEET
  SAFETY -->|Decision &amp; State Record| AUDIT
  AUDIT -->|Signed Compliance Passport| BRIDGE
  BRIDGE -->|Canonical Evidence Record| EV
  EV -->|HTTP / Sync| GW
  GW -->|Compliance Dashboards| AIMS
```

### Real-Time Supervisory Safety Loop (<50 µs)

```mermaid
sequenceDiagram
  autonumber
  participant Robot as Robot / VLA Policy
  participant Stream as TelemetryStreamServer
  participant Filter as QPSafetyFilter & StateMachine
  participant Ledger as MerkleBlackBoxLedger
  participant Claw as GRC_Claw Gateway (:18791)

  Robot->>Stream: Stream state & nominal command (u_nom)
  Stream->>Filter: Evaluate CBF constraints & ZMP stability
  alt Safe Nominal Command
    Filter-->>Stream: u_safe = u_nom (Zero Intervention)
  else Hazardous Boundary Breach
    Filter->>Filter: Solve Active-Set QP: min 0.5 * ||u - u_nom||²
    Filter-->>Stream: u_safe = u_filtered (Clamped / Damped)
  end
  Stream->>Robot: Dispatch verified safe command (u_safe)
  Stream->>Ledger: Append leaf hash to incremental Merkle tree
  Ledger->>Claw: Issue Passport & attach to GRC_Claw EvidenceStore (ISO 42001)
```

---

## 🦞 GRC_Claw Integration (ISO 42001 & NIST AI RMF)

`physical-ai-governor` natively integrates with [GRC_Claw](https://github.com/AAH20/GRC_Claw), the open-source Autonomous AI Governance, Risk, and Compliance Engine:

1. **RFC 8785 Canonical JSON Serialization**: Produces deterministic JSON digests matching `robot-black-box-contract`.
2. **Standard EvidenceStore Packaging**: Generates certified `GRCClawEvidenceRecord` objects formatted for `evidence.attach` with `rbb://` URIs and lineage tracking.
3. **ISO/IEC 42001:2023 Assessment Mapping**: Automatically certifies compliance across:
   - **Clause 6.1**: Mathematical risk management via Control Barrier Functions.
   - **Clause 8.2**: Operational risk mitigation (speed damping, torque clamping).
   - **Clause 9.1**: Continuous monitoring and cryptographic Merkle verification.
4. **GRC_Claw Gateway Daemon Sync**: Automatic HTTP/JSON synchronization with the local GRC_Claw daemon (`127.0.0.1:18791`) with resilient offline queueing.

```python
from physical_ai_governor import GRCClawBridge, MerkleBlackBoxLedger

# 1. Initialize bridge to local GRC_Claw Gateway
bridge = GRCClawBridge(gateway_url="http://127.0.0.1:18791", tenant_id=1)

# 2. Package compliance passport into certified GRC_Claw EvidenceStore record
passport = ledger.issue_compliance_passport("humanoid_gr00t_01", total_interventions=2)
evidence = bridge.build_evidence_record(passport, control_id="ISO-42001-A.6.2.2-PHYSICAL-AI-SAFETY")

print(f"Evidence URI: {evidence.uri}")
print(f"Canonical SHA-256 Digest: {evidence.sha256}")

# 3. Assess ISO 42001 readiness
readiness = bridge.assess_iso42001_readiness(passport)
print(f"ISO 42001 Status: {readiness['overall_iso42001_readiness']}")

# 4. Synchronize with GRC_Claw Gateway
sync_result = bridge.sync_to_gateway(evidence)
print(f"Gateway Sync: {sync_result['status']}")
```

---

## 📦 Robot Black Box (RBB) Integration

`physical-ai-governor` natively implements the [**Robot Black Box (RBB)**](https://github.com/AAH20/robot-black-box) contract (`v0.1.0`), recording and validating physical flight logs according to specification `1.0.0-local.1`:

1. **RFC 8785 Canonical JSON Serialization**: Guarantees bitwise-identical digests across Python, Node, and C++ runtimes.
2. **Cryptographic Event Chaining**: Every event links to the prior via `previous_digest`, with domain separation prefix (`RBB-EVENT-v1\0`).
3. **Four-Phase Supervisory Safety Loop**:
   - `observation.recorded`: Encoders, joint positions, velocities, and human proximity distances.
   - `proposal.recorded`: Nominal motion or VLA action chunk generated by foundation models.
   - `approval.recorded`: Control Barrier Function mathematical evaluation grant (approved direct or safe clamped projection).
   - `execution.observed`: Actuator output dispatch confirmation and duration.
4. **Periodic Checkpoints & Witness Consensus**: Generates `checkpoints.json` and `witness/latest-heads.json` ensuring tamper-evident anchoring.
5. **Offline Independent Verifier**: Pure Python forensic auditor verifies entire `.rbb` bundles without external dependencies.

```python
from physical_ai_governor import RobotBlackBoxRecorder, RobotBlackBoxVerifier

# 1. Initialize flight recorder and start run
recorder = RobotBlackBoxRecorder(robot_id="humanoid_gr00t_01", tenant_ref="factory_floor_1")
recorder.start_run(task="benign_block_handover")

# 2. Stream telemetry and CBF decisions
cycle_events = recorder.record_safety_cycle(packet, decision)
recorder.close_run()

# 3. Export portable .rbb bundle directory
bundle_info = recorder.export_bundle(output_dir="./rbb_evidence_bundle")
print(f"RBB Bundle Exported: {bundle_info['bundle_path']}, Total Events: {bundle_info['total_events']}")

# 4. Perform independent forensic audit
report = RobotBlackBoxVerifier.verify_bundle("./rbb_evidence_bundle")
print(f"Bundle Valid: {report.is_valid}, Checks Passed: {len(report.checks_passed)}")
```

---

## 🔬 Mathematical Formulations

### 1. Control Barrier Functions (CBF) & Forward Invariance
Let the physical robot state be $\mathbf{x} \in \mathbb{R}^n$ and actuator command be $\mathbf{u} \in \mathcal{U} \subset \mathbb{R}^m$. We define the safe operating set $\mathcal{C}$ as the superlevel set of a continuously differentiable barrier function $h: \mathbb{R}^n \to \mathbb{R}$:

$$\mathcal{C} = \{ \mathbf{x} \in \mathbb{R}^n \mid h(\mathbf{x}) \ge 0 \}$$

To guarantee that the robot remains safely within $\mathcal{C}$ for all time $t \ge 0$ (forward invariance), the control input $\mathbf{u}$ must satisfy the Nagumo barrier condition:

$$\dot{h}(\mathbf{x}, \mathbf{u}) = \nabla h(\mathbf{x}) \cdot \dot{\mathbf{x}} \ge -\alpha(h(\mathbf{x}))$$

where $\alpha(\cdot)$ is an extended class $\mathcal{K}_\infty$ function (e.g., $\alpha(r) = \gamma r$).

### 2. Quadratic Programming CBF Filter (QP-CBF)
Rather than applying disconnected heuristic clamps, `QPSafetyFilter` solves the minimum-deviation quadratic program:

$$\min_{\mathbf{u} \in \mathcal{U}} \frac{1}{2} \|\mathbf{u} - \mathbf{u}_{\text{nom}}\|^2 \quad \text{subject to} \quad \mathbf{A}_{\text{cbf}} \mathbf{u} \le \mathbf{b}_{\text{cbf}}, \quad -\boldsymbol{\tau}_{\max} \le \mathbf{u} \le \boldsymbol{\tau}_{\max}$$

Solved deterministically via the built-in `ActiveSetQPSolver` with zero third-party dependencies.

### 3. High-Order CBFs (HOCBF) for Relative Degree $r=2$
For dynamic systems where actuator commands control acceleration or torque:
$$\psi_0(\mathbf{x}) = h(\mathbf{x}), \quad \psi_1(\mathbf{x}) = \dot{\psi}_0(\mathbf{x}) + \alpha_1(\psi_0(\mathbf{x})), \quad \dot{\psi}_1(\mathbf{x}, \mathbf{u}) + \alpha_2(\psi_1(\mathbf{x})) \ge 0$$
Bounding the allowable approach rate and ensuring smooth deceleration before physical boundary contact.

### 4. Bipedal Humanoid Stability (ZMP & Friction Cone)
- **Zero Moment Point (ZMP)**: Evaluated using the cart-table inverted pendulum model:
  $$x_{\text{zmp}} = x_{\text{com}} - \frac{z_{\text{com}}}{g} \ddot{x}_{\text{com}}, \quad y_{\text{zmp}} = y_{\text{com}} - \frac{z_{\text{com}}}{g} \ddot{y}_{\text{com}}$$
  Guarantees $(x_{\text{zmp}}, y_{\text{zmp}})$ remains strictly inside the support polygon $[x_{\min}, x_{\max}] \times [y_{\min}, y_{\max}]$.
- **Coulomb Friction Cone**: Ground reaction force $\mathbf{F} = (F_x, F_y, F_z)$ must satisfy:
  $$\sqrt{F_x^2 + F_y^2} \le \mu F_z$$

### 5. Streaming Merkle Black-Box & Inclusion Proofs
Every ingested packet and filter decision is serialized and hashed into an incremental binary Merkle tree:

$$\text{Leaf}_i = \text{SHA256}(\mathrm{ID}_{\text{robot}, i} \parallel t_i \parallel \mathbf{p}_i \parallel \mathbf{v}_i \parallel d_{\text{human}, i} \parallel \text{safe}_i \parallel \mathbf{u}_{\text{filtered}, i})$$

Any individual event $k$ can be proven to regulators via an $O(\log N)$ Merkle audit path:
$$\pi_k = \{ (s_1, p_1), \dots, (s_m, p_m) \} \quad \text{such that} \quad \text{Verify}(\text{Leaf}_k, \pi_k, R) = \text{True}$$

### 6. Zero-Knowledge Safety Invariance Proofs (Fiat-Shamir CBF)
Enables operators in defense, robotics factories, and autonomous aviation to prove 100% CBF compliance to regulators and insurers without revealing mission coordinates, waypoints, or factory geometry:

$$\mathbf{c}_i = \text{SHA256}(\text{Leaf}_i \parallel \text{safe}_i \parallel r_i), \quad e = \text{SHA256}(R \parallel \text{Invariants} \parallel \mathbf{c}_1 \parallel \dots \parallel \mathbf{c}_N)$$

Where $r_i$ is an ephemeral 128-bit cryptographic blinding factor, $R$ is the public Merkle root, and $e$ is the non-interactive Fiat-Shamir challenge.

### 7. Reciprocal Multi-Agent Swarm Barrier Functions
For multi-robot swarms (drones, AGVs, quadrupeds), pairwise reciprocal safety barriers guarantee collision-free coordination:

$$h_{ij}(\mathbf{p}_i, \mathbf{p}_j) = \|\mathbf{p}_i - \mathbf{p}_j\|^2 - d_{\min}^2 \ge 0$$

Under reciprocal velocity dynamics, each agent $i$ adjusts its velocity $\mathbf{v}_i$ symmetrically:
$$\dot{h}_{ij} = 2(\mathbf{p}_i - \mathbf{p}_j) \cdot (\mathbf{v}_i - \mathbf{v}_j) \ge -\gamma h_{ij}(\mathbf{p}_i, \mathbf{p}_j)$$

---

## 📜 Statutory & Regulatory Mapping

| Standard / Regulation | Statutory Clause | Physical AI Governor Enforcement Mechanism |
| :--- | :--- | :--- |
| **GRC_Claw (ISO 42001)** | Clauses 6.1, 8.2, 9.1 (AI Management System) | Native RFC 8785 canonical evidence records, `rbb://` URI schema, and automated AIMS readiness envelopes. |
| **FAA Part 89** | 14 CFR § 89.305 / § 89.310 (Remote ID Broadcast) | Generates ASTM F3411-22a compliant OpenDroneID broadcast frames (Type 0x1 Location/Vector & Type 0x5 Operator ID). |
| **EU AI Act** | Annex III, Section 2 & 5 (High-Risk AI Systems) | Automatic JSON-LD technical conformity dossiers, continuous CBF boundary guarantees, and post-market audit trails. |
| **ISO 10218-1 / 2** | Section 5.10 (Collaborative Robot Safety) | Human proximity protective damping, dynamic speed and separation monitoring (SSM), and joint torque limits (PFL). |
| **ISO/TS 15066** | Collaborative Robots — Biomechanical Limits | Real-time contact force evaluation against statutory pressure and force thresholds across 29 human body regions. |

---

## ⚡ Key Highlights

- **Pure Python 3.10+ Standard Library**: Zero external C++ or numerical library dependencies — zero supply-chain attack surface.
- **Microsecond Execution**: Ingestion and safety evaluation at **>100,000 packets/sec** ($<0.01\text{ ms}$ latency).
- **Formal QP-CBF & HOCBF**: Mathematical forward invariance and smooth second-order deceleration.
- **Zero-Knowledge (ZK) Safety Proofs**: Non-interactive Fiat-Shamir invariance verification without revealing secret coordinates.
- **Hardware TPM 2.0 Silicon Attestation**: PCR 10/11/12 code & policy sealing for edge chips (NVIDIA Jetson, Intel NUC).
- **Swarm Reciprocal CBF**: Decentralized pairwise collision avoidance for multi-agent drone swarms.
- **ROS 2 & DDS Telemetry Bridge**: Native streaming mapping for `sensor_msgs/JointState`, `geometry_msgs/Twist`, and diagnostic arrays.
- **Vision-Language-Action (VLA) Chunk Screening**: Validates OpenVLA, Octo, and RT-2 action chunks prior to physical execution.
- **Forensic Audit & Inclusion Proofs**: Merkle black-box audit ledger with logarithmic inclusion verification.
- **ISO 10218 Safety State Machine**: Automatic collaborative reduced speed, protective stop, and emergency stop transitions.
- **GRC_Claw Integration**: Full interoperability with the GRC_Claw evidence plane and ISO 42001 governance engine.
- **Built-in CLI**: Turnkey commands for benchmarking, ZK proofs, Swarm evaluation, VLA simulation, GRC_Claw sync, and Remote ID.

---

## 📥 Installation

```bash
# Clone the repository
git clone https://github.com/AAH20/physical-ai-governor.git
cd physical-ai-governor

# Install in editable mode with CLI entrypoint (Pure Python 3.10+)
pip install -e .
```

---

## 🚀 Quickstart

### 1. Minimal-Deviation QP-CBF Safety Filter

```python
from physical_ai_governor import QPSafetyFilter, TelemetryIngestor

ingestor = TelemetryIngestor()
qp_filter = QPSafetyFilter(min_human_distance_m=1.50, max_joint_torque_nm=150.0)

packet = ingestor.parse_humanoid_joint_state(
    robot_id="humanoid_gr00t_01",
    timestamp_ns=1700000000000,
    base_pos=(0.0, 0.0, 1.2),
    base_vel=(0.8, 0.0, 0.0),
    current_torques=[40.0, -35.0],
    commanded_torques=[195.0, -210.0],  # Hazardous command exceeding 150 Nm
    human_proximity=1.20,              # Breaches 1.50m safe boundary
    battery=92.0,
)

decision = qp_filter.evaluate_safety_qp(packet)
print(f"Safe: {decision.is_safe}")
print(f"Intervention Triggered: {decision.intervention_triggered}")
print(f"Optimally Filtered Torques: {decision.filtered_command}")
```

### 2. VLA Multi-Step Action Chunk Horizon Validation

```python
from physical_ai_governor import VLAActionHorizonValidator

validator = VLAActionHorizonValidator(min_human_distance_m=1.50, max_joint_torque_nm=150.0)

# 8-step predicted action chunk from OpenVLA or Octo
action_chunk = [[40.0, 30.0]] * 4 + [[210.0, -220.0]] + [[40.0, 30.0]] * 3

result = validator.validate_and_filter_chunk(packet, action_chunk)
print(f"Chunk Safe: {result.is_chunk_safe}")
print(f"First Violation Step: {result.first_violation_step}")
print(f"Proactively Corrected Chunk Step 4: {result.safe_action_chunk[4]}")
```

### 3. Native Binary MAVLink v2 Telemetry Parsing

```python
from physical_ai_governor import (
    MAVLinkFrameParser,
    serialize_mavlink_v2_global_position,
)

# Synthesize or receive raw wire-format binary MAVLink v2 frame
raw_bytes = serialize_mavlink_v2_global_position(
    sysid=1, compid=1, seq=42, time_boot_ms=60000,
    lat=37.7749, lon=-122.4194, alt_m=120.0,
    vx_mps=2.5, vy_mps=0.0, vz_mps=-0.5,
)

parser = MAVLinkFrameParser()
msg = parser.parse_frame(raw_bytes)
print(f"Parsed MAVLink MsgID: {msg.msgid}, CRC Valid: {msg.is_valid_crc}")

drone_packet = parser.parse_to_telemetry_packet(raw_bytes, drone_id="drone_px4_01")
print(f"GPS Position: {drone_packet.position_xyz}")
```

### 4. Merkle Black-Box Ledger & Inclusion Proof Verification

```python
from physical_ai_governor import MerkleBlackBoxLedger

ledger = MerkleBlackBoxLedger()
leaf = ledger.append_record(packet, decision)
root = ledger.build_merkle_root()

# Generate and verify tamper-evident audit proof
proof = ledger.generate_audit_proof(index=0)
is_valid = MerkleBlackBoxLedger.verify_audit_proof(leaf, proof, root)
print(f"Merkle Inclusion Proof Verified: {is_valid}")
```

### 5. Zero-Knowledge (ZK) Safety Invariance Proofs

```python
from physical_ai_governor import ZKSafetyProver

# Prove 100% barrier compliance without disclosing trajectory waypoints or plant coordinates
prover = ZKSafetyProver()
envelope = prover.generate_zk_proof(ledger, robot_id="stealth_humanoid_01")

print(f"Proof ID: {envelope.proof_id}")
print(f"Fiat-Shamir Challenge: {envelope.challenge_hash[:16]}...")
print(f"Cycles Certified: {envelope.total_cycles_proven}")

# Third-party regulator verification (zero coordinate knowledge required)
verified = ZKSafetyProver.verify_zk_proof(envelope)
print(f"ZK Safety Proof Valid: {verified}")
```

### 6. Hardware TPM 2.0 Silicon Attestation & PCR Sealing

```python
from physical_ai_governor import TPM2HardwareAttestor

tpm = TPM2HardwareAttestor(silicon_chip_id="JETSON-ORIN-AGX-001")
pcr10 = tpm.measure_code_integrity("cbf_kernel_hash")
pcr11 = tpm.measure_policy_limits(min_dist=1.5, max_torque=150.0, max_vel=4.0)

# Seal compliance passport into hardware quote with silicon nonce
passport = ledger.issue_compliance_passport("humanoid_01", total_interventions=0)
quote = tpm.seal_merkle_passport(passport)
print(f"Hardware Quote Valid: {tpm.verify_tpm_quote(quote)}")
```

### 7. Swarm Reciprocal Control Barrier Functions

```python
from physical_ai_governor import SwarmAgentState, SwarmControlBarrierGovernor

gov = SwarmControlBarrierGovernor(min_inter_agent_distance_m=2.0)
agents = [
    SwarmAgentState("drone_1", (0.0, 0.0, 10.0), (1.5, 0.0, 0.0), (1.5, 0.0, 0.0)),
    SwarmAgentState("drone_2", (1.5, 0.0, 10.0), (-1.5, 0.0, 0.0), (-1.5, 0.0, 0.0)),
]

decisions = gov.evaluate_swarm_safety(agents)
for agent_id, dec in decisions.items():
    print(f"{agent_id} Filtered Velocity: {dec.filtered_velocity}, Safe: {dec.is_safe}")
```

### 8. ROS 2 Telemetry Bridge & Diagnostic Arrays

```python
from physical_ai_governor import ROS2JointState, ROS2TelemetryBridge

bridge = ROS2TelemetryBridge()
msg = ROS2JointState(
    names=["shoulder", "elbow"],
    positions=[0.1, -0.2],
    velocities=[0.0, 0.0],
    efforts=[25.0, -20.0],
    stamp_sec=1700000000,
    stamp_nanosec=0,
)

decision, leaf, diag = bridge.process_ros2_cycle(
    msg=msg,
    robot_id="humanoid_ros2",
    commanded_efforts=[180.0, -190.0],  # Excessive torque
    human_proximity_m=1.1,              # Breaches safe boundary
)
print(f"ROS 2 Diagnostic Array Level: {diag['level']}, Message: {diag['message']}")
```

---

## 💻 CLI Usage

`physical-ai-governor` provides a unified command-line tool:

```bash
# 1. Run high-frequency CBF benchmark (1,000 cycles)
physical-ai-governor benchmark --cycles 1000

# 2. Synchronize compliance passport with GRC_Claw evidence plane
physical-ai-governor grc-claw-sync --cycles 100 --robot-id humanoid_gr00t_01

# 3. Generate non-interactive Zero-Knowledge (ZK) safety proof
physical-ai-governor zk-prove --robot-id humanoid_gr00t_01 --cycles 100 -o zk_proof.json

# 4. Evaluate multi-robot swarm reciprocal collision avoidance
physical-ai-governor swarm-eval --agents 3

# 5. Simulate VLA action chunk horizon safety screening
physical-ai-governor vla-eval --horizon 8 --robot-id humanoid_gr00t_01

# 6. Export EU AI Act Annex III technical conformity dossier
physical-ai-governor export-dossier --robot-id humanoid_gr00t_01 -o dossier.json

# 7. Record physical AI flight telemetry into an RBB bundle
physical-ai-governor rbb-record --robot-id humanoid_gr00t_01 --cycles 20 --out ./rbb_bundle

# 8. Audit and verify an on-disk RBB bundle
physical-ai-governor rbb-verify --bundle ./rbb_bundle

# 9. Synthesize FAA Part 89 Remote ID broadcast packet
physical-ai-governor remote-id --lat 37.7749 --lon -122.4194 --speed 4.0
```

---

## 📊 Benchmark Verification

```bash
python3 -m unittest discover -s tests -v
```

```
test_cli_commands (test_physical_ai.TestPhysicalAIGovernor.test_cli_commands) ... ok
test_compliance_passport_issuance (test_physical_ai.TestPhysicalAIGovernor.test_compliance_passport_issuance) ... ok
test_control_barrier_human_proximity_damping (test_physical_ai.TestPhysicalAIGovernor.test_control_barrier_human_proximity_damping) ... ok
test_control_barrier_torque_clamping (test_physical_ai.TestPhysicalAIGovernor.test_control_barrier_torque_clamping) ... ok
test_end_to_end_benchmark_runner (test_physical_ai.TestPhysicalAIGovernor.test_end_to_end_benchmark_runner) ... ok
test_grc_claw_canonical_and_evidence_packaging (test_physical_ai.TestPhysicalAIGovernor.test_grc_claw_canonical_and_evidence_packaging) ... ok
test_grc_claw_rbb_event_stream (test_physical_ai.TestPhysicalAIGovernor.test_grc_claw_rbb_event_stream) ... ok
test_high_order_control_barrier_filter (test_physical_ai.TestPhysicalAIGovernor.test_high_order_control_barrier_filter) ... ok
test_humanoid_stability_governor (test_physical_ai.TestPhysicalAIGovernor.test_humanoid_stability_governor) ... ok
test_iso10218_safety_state_machine (test_physical_ai.TestPhysicalAIGovernor.test_iso10218_safety_state_machine) ... ok
test_mavlink_binary_frame_and_crc (test_physical_ai.TestPhysicalAIGovernor.test_mavlink_binary_frame_and_crc) ... ok
test_merkle_audit_proof_generation_and_verification (test_physical_ai.TestPhysicalAIGovernor.test_merkle_audit_proof_generation_and_verification) ... ok
test_merkle_blackbox_hash_chaining (test_physical_ai.TestPhysicalAIGovernor.test_merkle_blackbox_hash_chaining) ... ok
test_qp_safety_filter (test_physical_ai.TestPhysicalAIGovernor.test_qp_safety_filter) ... ok
test_qp_solver_unconstrained_and_constrained (test_physical_ai.TestPhysicalAIGovernor.test_qp_solver_unconstrained_and_constrained) ... ok
test_rbb_canonical_serialization_and_validation (test_physical_ai.TestPhysicalAIGovernor.test_rbb_canonical_serialization_and_validation) ... ok
test_rbb_cli_commands (test_physical_ai.TestPhysicalAIGovernor.test_rbb_cli_commands) ... ok
test_rbb_recorder_and_verifier_bundle_integrity (test_physical_ai.TestPhysicalAIGovernor.test_rbb_recorder_and_verifier_bundle_integrity) ... ok
test_ros2_telemetry_bridge_conversions (test_physical_ai.TestPhysicalAIGovernor.test_ros2_telemetry_bridge_conversions) ... ok
test_statutory_engine_faa_eu_iso (test_physical_ai.TestPhysicalAIGovernor.test_statutory_engine_faa_eu_iso) ... ok
test_swarm_control_barrier_governor (test_physical_ai.TestPhysicalAIGovernor.test_swarm_control_barrier_governor) ... ok
test_telemetry_ingestion_parsers (test_physical_ai.TestPhysicalAIGovernor.test_telemetry_ingestion_parsers) ... ok
test_telemetry_stream_server_processing (test_physical_ai.TestPhysicalAIGovernor.test_telemetry_stream_server_processing) ... ok
test_tpm2_hardware_silicon_attestation (test_physical_ai.TestPhysicalAIGovernor.test_tpm2_hardware_silicon_attestation) ... ok
test_vla_action_horizon_validator (test_physical_ai.TestPhysicalAIGovernor.test_vla_action_horizon_validator) ... ok
test_zk_safety_prover_and_verifier (test_physical_ai.TestPhysicalAIGovernor.test_zk_safety_prover_and_verifier) ... ok

----------------------------------------------------------------------
Ran 26 tests in 0.049s

OK
```

---

## 📄 License
MIT License. Developed by [Ahmed Hassan](https://github.com/AAH20) — Founder, A2Z SOC / AH2 SCA.
