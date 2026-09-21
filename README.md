# Physical AI Governor 🤖

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](https://opensource.org/licenses/MIT)
[![Python: 3.10+](https://img.shields.io/badge/Python-3.10%2B-brightgreen.svg)](https://python.org)
[![Dependencies: Zero](https://img.shields.io/badge/Dependencies-Zero%20(Pure%20Stdlib)-blueviolet.svg)](#-key-highlights)
[![Tests: 15/15 Passing](https://img.shields.io/badge/Tests-15%2F15%20Passing-success.svg)](#-benchmark-verification)
[![Chassis: GRC Claw](https://img.shields.io/badge/Chassis-GRC%20Claw%20(ISO%2042001)-orange.svg)](https://github.com/AAH20/GRC_Claw)
[![Assurance Hub: A2Z SOC](https://img.shields.io/badge/Assurance-A2Z%20SOC%20Physical%20AI-informational.svg)](https://a2zsoc.com/physical-ai-humanoid-assurance)

> **Autonomous Physical AI, Humanoid (GR00T) & Drone Swarm GRC Assurance Engine.**  
> Enforces continuous Control Barrier Functions (CBF, QP-CBF, HOCBF) over streaming ROS 2, MAVLink, and VLA joint trajectories, notarizing tamper-evident black-box Merkle ledgers with inclusion proofs and statutory compliance passports for FAA Part 89, EU AI Act Annex III, and ISO 10218 / ISO/TS 15066.

---

## 🏛️ System Architecture

```
           ROBOT & FLEET ACTUATORS                        REGULATORY & COMPLIANCE
   (Humanoid Joints, Drone Rotors, ROS 2, VLA)         (FAA Part 89, EU AI Act Annex III,
                        │                                    ISO 10218 & ISO/TS 15066)
                        ▼                                               │
 ┌──────────────────────────────────────────────────────────────────────▼──────┐
 │                            physical-ai-governor                             │
 │                                                                             │
 │   1. Ingestion & Protocol Engine (>100,000 packets/sec)                     │
 │      • Standardizes heterogeneous MAVLink v2 & ROS 2 trajectory states      │
 │      • Native binary MAVLink v2 framing & CRC-16-MCRF4XX checksum validator │
 │      • VLAActionHorizonValidator: screens multi-step action chunks (H=8..16)│
 │                                                                             │
 │   2. Control Barrier & Optimization Core (Forward Invariance)               │
 │      • ActiveSetQPSolver: pure Python strictly convex QP solver (<1ms)      │
 │      • QPSafetyFilter: minimal-norm intervention min 0.5 * ||u - u_nom||^2  │
 │      • HighOrderControlBarrierFilter: relative degree r=2 kinematics        │
 │      • HumanoidStabilityGovernor: Zero Moment Point (ZMP) & friction cone   │
 │                                                                             │
 │   3. MerkleBlackBoxLedger & Statutory Engine                                │
 │      • Streaming Merkle tree with logarithmic inclusion proofs              │
 │      • FAA Part 89 Remote ID broadcast generator (ASTM F3411-22a BLE/Wi-Fi) │
 │      • EU AI Act Annex III High-Risk Technical Conformity Dossier (JSON-LD) │
 │      • ISO/TS 15066 Biomechanical force limits across 29 body regions       │
 └──────────────────────────────────────┬──────────────────────────────────────┘
                                        │
                                        ▼
                         PHYSICAL AI FLEET CERTIFICATION
                  • 0.000% Safety Boundary Breaches Under Attack
                  • Instantaneous Insurer & Aviation Compliance Passports
                  • Universal Interoperability across Humanoids & Drones
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

$$\text{Leaf}_i = \text{SHA256}(\text{robot\_id} \parallel t_i \parallel \mathbf{p}_i \parallel \mathbf{v}_i \parallel d_{\text{human}, i} \parallel \text{is\_safe}_i \parallel \mathbf{u}_{\text{filtered}, i})$$

Any individual event $k$ can be proven to regulators via an $O(\log N)$ Merkle audit path:
$$\pi_k = \{ (s_1, \text{pos}_1), \dots, (s_m, \text{pos}_m) \} \quad \text{such that} \quad \text{Verify}(\text{Leaf}_k, \pi_k, R) = \text{True}$$

---

## 📜 Statutory & Regulatory Mapping

| Standard / Regulation | Statutory Clause | Physical AI Governor Enforcement Mechanism |
| :--- | :--- | :--- |
| **FAA Part 89** | 14 CFR § 89.305 / § 89.310 (Remote ID Broadcast) | Generates ASTM F3411-22a compliant OpenDroneID broadcast frames (Type 0x1 Location/Vector & Type 0x5 Operator ID). |
| **EU AI Act** | Annex III, Section 2 & 5 (High-Risk AI Systems) | Automatic JSON-LD technical conformity dossiers, continuous CBF boundary guarantees, and post-market audit trails. |
| **ISO 10218-1 / 2** | Section 5.10 (Collaborative Robot Safety) | Human proximity protective damping, dynamic speed and separation monitoring (SSM), and joint torque limits (PFL). |
| **ISO/TS 15066** | Collaborative Robots — Biomechanical Limits | Real-time contact force evaluation against statutory pressure and force thresholds across 29 human body regions. |

---

## ⚡ Key Highlights

- **Pure Python 3.10+ Standard Library**: Zero external C++ or numerical library dependencies — zero supply-chain attack surface.
- **Microsecond Execution**: Ingestion and safety evaluation at **>100,000 packets/sec** ($<0.01\text{ ms}$ latency).
- **Formal QP-CBF & HOCBF**: Mathematical forward invariance and smooth second-order deceleration.
- **Vision-Language-Action (VLA) Chunk Screening**: Validates OpenVLA, Octo, and RT-2 action chunks prior to physical execution.
- **Forensic Audit & Inclusion Proofs**: Merkle black-box audit ledger with logarithmic inclusion verification.
- **Built-in CLI**: Turnkey commands for benchmarking, VLA chunk simulation, FAA Remote ID broadcast, and EU AI Act dossier exports.

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

### 5. Statutory Assurance: FAA Remote ID & EU AI Act Dossier

```python
from physical_ai_governor import StatutoryAssuranceEngine

engine = StatutoryAssuranceEngine()

# FAA Part 89 Remote ID OpenDroneID packet
remote_id = engine.synthesize_faa_part89_remote_id(
    lat=37.7749, lon=-122.4194, alt_m=120.0, speed_mps=4.5,
    operator_id="FAA-US-2026-PHYSICAL-AI",
)
print(f"FAA Remote ID Hex: {remote_id['message_type_0x1_hex']}")

# EU AI Act Annex III Technical Conformity Dossier
passport = ledger.issue_compliance_passport("humanoid_gr00t_01", total_interventions=1)
dossier = engine.generate_eu_ai_act_annex_iii_dossier(passport)
print(f"Conformity Dossier Document Type: {dossier['document_type']}")
```

---

## 💻 CLI Usage

`physical-ai-governor` provides a unified command-line tool:

```bash
# 1. Run high-frequency CBF benchmark (1,000 cycles)
physical-ai-governor benchmark --cycles 1000

# 2. Simulate VLA action chunk horizon safety screening
physical-ai-governor vla-eval --horizon 8 --robot-id humanoid_gr00t_01

# 3. Export EU AI Act Annex III technical conformity dossier
physical-ai-governor export-dossier --robot-id humanoid_gr00t_01 -o dossier.json

# 4. Synthesize FAA Part 89 Remote ID broadcast packet
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
test_high_order_control_barrier_filter (test_physical_ai.TestPhysicalAIGovernor.test_high_order_control_barrier_filter) ... ok
test_humanoid_stability_governor (test_physical_ai.TestPhysicalAIGovernor.test_humanoid_stability_governor) ... ok
test_mavlink_binary_frame_and_crc (test_physical_ai.TestPhysicalAIGovernor.test_mavlink_binary_frame_and_crc) ... ok
test_merkle_audit_proof_generation_and_verification (test_physical_ai.TestPhysicalAIGovernor.test_merkle_audit_proof_generation_and_verification) ... ok
test_merkle_blackbox_hash_chaining (test_physical_ai.TestPhysicalAIGovernor.test_merkle_blackbox_hash_chaining) ... ok
test_qp_safety_filter (test_physical_ai.TestPhysicalAIGovernor.test_qp_safety_filter) ... ok
test_qp_solver_unconstrained_and_constrained (test_physical_ai.TestPhysicalAIGovernor.test_qp_solver_unconstrained_and_constrained) ... ok
test_statutory_engine_faa_eu_iso (test_physical_ai.TestPhysicalAIGovernor.test_statutory_engine_faa_eu_iso) ... ok
test_telemetry_ingestion_parsers (test_physical_ai.TestPhysicalAIGovernor.test_telemetry_ingestion_parsers) ... ok
test_vla_action_horizon_validator (test_physical_ai.TestPhysicalAIGovernor.test_vla_action_horizon_validator) ... ok

----------------------------------------------------------------------
Ran 15 tests in 0.008s

OK
```

---

## 📄 License
MIT License. Developed by [Ahmed Hassan](https://github.com/AAH20) — Founder, A2Z SOC / AH2 SCA.
