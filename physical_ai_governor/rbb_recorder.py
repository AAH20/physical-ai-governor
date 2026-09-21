"""
Robot Black Box (RBB) Streaming Flight Recorder.
Compatible with the https://github.com/AAH20/robot-black-box specification.
Records streaming Physical AI telemetry and Control Barrier Function (CBF)
interventions into cryptographically chained, witness-attested .rbb bundles.
Note: Built-in witness receipt generation simulates an independent witness service
within the local process for testing and demonstration. Production deployments
must obtain witness receipts and latest-heads attestations from physically separate witness nodes.
Pure Python 3.10+ standard library (zero external dependencies).
"""

import base64
import hashlib
import hmac
import json
import os
import pathlib
import secrets
import time
from typing import Any, Dict, List, Optional, Set, Tuple

from .control_barrier import SafetyDecision
from .rbb_contract import (
    DOMAINS,
    SCHEMA_VERSION,
    ZERO,
    canonical_json,
    compute_rbb_digest,
    sha256_hex,
    validate_rbb_event,
)
from .telemetry_ingest import RobotTelemetryPacket


class RobotBlackBoxRecorder:
    """
    Streaming black-box event recorder for humanoid robots, drones, and autonomous systems.
    Constructs an unbroken SHA-256 hash-chained event log with domain-separated signing,
    periodic checkpoints, and local witness receipts.
    """

    def __init__(
        self,
        robot_id: str,
        run_id: Optional[str] = None,
        tenant_ref: str = "tenant-default",
        system_id: Optional[str] = None,
        producer_id: str = "producer-governor",
        signing_key_id: str = "prod-key-01",
        signing_secret: Optional[str] = None,
        witness_key_id: str = "witness-local-01",
        witness_secret: Optional[str] = None,
    ) -> None:
        self.robot_id = robot_id
        self.run_id = run_id or f"run-{int(time.time())}-{secrets.token_hex(4)}"
        self.tenant_ref = tenant_ref
        self.system_id = system_id or f"sys-{robot_id}"
        self.stream_id = f"stream-{robot_id}-safety"
        self.producer_id = producer_id
        self.boot_id = f"boot-{secrets.token_hex(8)}"
        self.signing_key_id = signing_key_id
        self.signing_secret = (signing_secret or secrets.token_hex(32)).encode("utf-8")
        self.witness_key_id = witness_key_id
        self.witness_secret = (witness_secret or secrets.token_hex(32)).encode("utf-8")

        self.config_digest = sha256_hex(b"default_rbb_cbf_config")
        self.policy_digest = sha256_hex(b"iso10218_cbf_safety_policy")

        self.sequence = 0
        self.previous_digest = ZERO
        self.events: List[Dict[str, Any]] = []
        self.checkpoints: List[Dict[str, Any]] = []
        self.event_ids: Set = set()
        self.is_open = False
        self.is_closed = False

    def get_trusted_keys(self) -> Dict[str, Any]:
        """Returns trusted signing secrets for external verifier validation."""
        return {
            "producers": {
                self.signing_key_id: self.signing_secret.decode("utf-8"),
            },
            "witnesses": {
                self.witness_key_id: self.witness_secret.decode("utf-8"),
            },
        }

    def get_trusted_witnesses(self) -> Dict[str, str]:
        """Returns witness key ID to secret mapping."""
        return {self.witness_key_id: self.witness_secret.decode("utf-8")}

    def get_trusted_producers(self) -> Dict[str, str]:
        """Returns producer key ID to secret mapping."""
        return {self.signing_key_id: self.signing_secret.decode("utf-8")}

    def _sign_record(
        self,
        body: Dict[str, Any],
        domain: str,
        key_id: Optional[str] = None,
        secret: Optional[bytes] = None,
    ) -> Dict[str, Any]:
        """Signs an RBB record body using domain separation prefix."""
        active_key_id = key_id or self.signing_key_id
        active_secret = secret if secret is not None else self.signing_secret

        body_canon = canonical_json(body)
        body_bytes = body_canon.encode("utf-8")
        event_digest = sha256_hex(body_bytes)

        # Domain separated signature prefix: RBB-{domain}-v1\0
        domain_prefix = f"RBB-{domain}-v1\0".encode("utf-8")
        msg = domain_prefix + bytes.fromhex(event_digest)

        # Generate HMAC-SHA256 signature representation for portable bundle
        sig_bytes = hmac.new(active_secret, msg, hashlib.sha256).digest()
        # Pad or represent as 64-byte signature string (or base64 encoded)
        sig_b64 = base64.b64encode(sig_bytes * 2).decode("ascii")  # 64 bytes for ed25519 length parity

        signed_record = dict(body)
        signed_record["authentication"] = {
            "algorithm": "sha256-hmac",
            "key_id": active_key_id,
            "event_digest": event_digest,
            "signature": sig_b64,
        }
        return signed_record

    def _iso_timestamp(self) -> str:
        """Returns UTC ISO-8601 timestamp string ending in Z."""
        return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())

    def start_run(self, task: str = "benign_block_handover") -> Dict[str, Any]:
        """Emits the initial 'run.started' event and opens recording."""
        if self.is_open:
            raise RuntimeError("Recorder already started")

        self.sequence += 1
        now = self._iso_timestamp()
        event_id = f"evt-{self.run_id}-start"
        self.event_ids.add(event_id)

        body = {
            "schema_version": SCHEMA_VERSION,
            "event_id": event_id,
            "tenant_ref": self.tenant_ref,
            "system_id": self.system_id,
            "run_id": self.run_id,
            "stream_id": self.stream_id,
            "producer_id": self.producer_id,
            "boot_id": self.boot_id,
            "sequence": self.sequence,
            "event_type": "run.started",
            "observed_at": now,
            "received_at": now,
            "monotonic_ns": str(time.monotonic_ns()),
            "clock": {
                "clock_id": "clock-monotonic-utc",
                "status": "synchronized",
                "max_uncertainty_ms": 1.0,
            },
            "mode": "synthetic_replay",
            "causal_refs": [],
            "provenance": {
                "adapter_name": "physical_ai_governor_adapter",
                "adapter_version": "0.1.0",
                "source_kind": "stream_socket",
                "source_digest": self.config_digest,
                "source_offsets": [0],
                "claim_class": "synthetic",
            },
            "config_digest": self.config_digest,
            "policy_digest": self.policy_digest,
            "payload": {
                "task": task,
                "required_streams": [self.stream_id],
                "trust_profile": "local_replay_witnessed",
                "source_digest": self.config_digest,
            },
            "artifact_refs": [],
            "privacy": {
                "classification": "public_synthetic",
                "purpose_id": "cbf_safety_assurance",
                "retention_policy_id": "retain_30_days",
            },
            "previous_digest": self.previous_digest,
        }

        signed_event = self._sign_record(body, DOMAINS["EVENT"])
        validate_rbb_event(signed_event)

        self.events.append(signed_event)
        self.previous_digest = signed_event["authentication"]["event_digest"]
        self.is_open = True
        return signed_event

    def record_safety_cycle(
        self,
        packet: RobotTelemetryPacket,
        decision: SafetyDecision,
    ) -> List[Dict[str, Any]]:
        """
        Translates a single physical AI control cycle into an RBB 4-event sequence:
            1. observation.recorded (sensor packet)
            2. proposal.recorded (nominal action)
            3. approval.recorded (CBF filter evaluation grant)
            4. execution.observed (dispatched safe action)
        """
        if not self.is_open or self.is_closed:
            raise RuntimeError("Recorder must be open to record cycles")

        cycle_events = []
        now = self._iso_timestamp()
        mono_ns = str(time.monotonic_ns())

        # 1. Observation
        self.sequence += 1
        obs_id = f"evt-{self.run_id}-obs-{self.sequence}"
        self.event_ids.add(obs_id)
        obs_body = {
            "schema_version": SCHEMA_VERSION,
            "event_id": obs_id,
            "tenant_ref": self.tenant_ref,
            "system_id": self.system_id,
            "run_id": self.run_id,
            "stream_id": self.stream_id,
            "producer_id": self.producer_id,
            "boot_id": self.boot_id,
            "sequence": self.sequence,
            "event_type": "observation.recorded",
            "observed_at": now,
            "received_at": now,
            "monotonic_ns": mono_ns,
            "clock": {"clock_id": "clock-monotonic-utc", "status": "synchronized", "max_uncertainty_ms": 1.0},
            "mode": "synthetic_replay",
            "causal_refs": [self.events[-1]["event_id"]],
            "provenance": {
                "adapter_name": "physical_ai_governor_adapter",
                "adapter_version": "0.1.0",
                "source_kind": "stream_socket",
                "source_digest": self.config_digest,
                "source_offsets": [self.sequence],
                "claim_class": "synthetic",
            },
            "config_digest": self.config_digest,
            "policy_digest": self.policy_digest,
            "payload": {
                "sensor_id": f"{packet.robot_type}_joint_encoders",
                "frame_index": self.sequence,
                "value": f"pos={packet.position_xyz},dist={packet.human_distance_meters:.3f}m",
                "units": "si_units",
                "coordinate_frame": "world_enu",
                "evidence_status": "synthetic",
            },
            "artifact_refs": [],
            "privacy": {"classification": "public_synthetic", "purpose_id": "cbf_safety_assurance", "retention_policy_id": "retain_30_days"},
            "previous_digest": self.previous_digest,
        }
        signed_obs = self._sign_record(obs_body, DOMAINS["EVENT"])
        validate_rbb_event(signed_obs)
        self.events.append(signed_obs)
        self.previous_digest = signed_obs["authentication"]["event_digest"]
        cycle_events.append(signed_obs)

        # 2. Proposal
        self.sequence += 1
        prop_id = f"evt-{self.run_id}-prop-{self.sequence}"
        self.event_ids.add(prop_id)
        prop_body = {
            "schema_version": SCHEMA_VERSION,
            "event_id": prop_id,
            "tenant_ref": self.tenant_ref,
            "system_id": self.system_id,
            "run_id": self.run_id,
            "stream_id": self.stream_id,
            "producer_id": self.producer_id,
            "boot_id": self.boot_id,
            "sequence": self.sequence,
            "event_type": "proposal.recorded",
            "observed_at": now,
            "received_at": now,
            "monotonic_ns": mono_ns,
            "clock": {"clock_id": "clock-monotonic-utc", "status": "synchronized", "max_uncertainty_ms": 1.0},
            "mode": "synthetic_replay",
            "causal_refs": [obs_id],
            "provenance": {
                "adapter_name": "physical_ai_governor_adapter",
                "adapter_version": "0.1.0",
                "source_kind": "stream_socket",
                "source_digest": self.config_digest,
                "source_offsets": [self.sequence],
                "claim_class": "synthetic",
            },
            "config_digest": self.config_digest,
            "policy_digest": self.policy_digest,
            "payload": {
                "action_id": f"act-{self.sequence}",
                "input_refs": [obs_id],
                "requested_scope": "benign_block_handover",
                "model_revision": "physical_ai_vla_v1",
                "action_representation": f"cmd_torques={packet.command_torque_input}",
            },
            "artifact_refs": [],
            "privacy": {"classification": "public_synthetic", "purpose_id": "cbf_safety_assurance", "retention_policy_id": "retain_30_days"},
            "previous_digest": self.previous_digest,
        }
        signed_prop = self._sign_record(prop_body, DOMAINS["EVENT"])
        validate_rbb_event(signed_prop)
        self.events.append(signed_prop)
        self.previous_digest = signed_prop["authentication"]["event_digest"]
        cycle_events.append(signed_prop)

        # 3. Approval
        self.sequence += 1
        appr_id = f"evt-{self.run_id}-appr-{self.sequence}"
        self.event_ids.add(appr_id)
        grant = {
            "grant_id": f"grant-{self.sequence}",
            "action_id": f"act-{self.sequence - 1}",
            "status": "approved_filtered" if decision.intervention_triggered else "approved_direct",
            "filtered": decision.intervention_triggered,
            "barrier_margin_m": decision.cbf_margin,
            "reason": decision.violation_reason or "within_forward_invariant_barrier",
        }
        appr_body = {
            "schema_version": SCHEMA_VERSION,
            "event_id": appr_id,
            "tenant_ref": self.tenant_ref,
            "system_id": self.system_id,
            "run_id": self.run_id,
            "stream_id": self.stream_id,
            "producer_id": self.producer_id,
            "boot_id": self.boot_id,
            "sequence": self.sequence,
            "event_type": "approval.recorded",
            "observed_at": now,
            "received_at": now,
            "monotonic_ns": mono_ns,
            "clock": {"clock_id": "clock-monotonic-utc", "status": "synchronized", "max_uncertainty_ms": 1.0},
            "mode": "synthetic_replay",
            "causal_refs": [prop_id],
            "provenance": {
                "adapter_name": "physical_ai_governor_adapter",
                "adapter_version": "0.1.0",
                "source_kind": "stream_socket",
                "source_digest": self.config_digest,
                "source_offsets": [self.sequence],
                "claim_class": "synthetic",
            },
            "config_digest": self.config_digest,
            "policy_digest": self.policy_digest,
            "payload": {
                "grant": grant,
            },
            "artifact_refs": [],
            "privacy": {"classification": "public_synthetic", "purpose_id": "cbf_safety_assurance", "retention_policy_id": "retain_30_days"},
            "previous_digest": self.previous_digest,
        }
        signed_appr = self._sign_record(appr_body, DOMAINS["EVENT"])
        validate_rbb_event(signed_appr)
        self.events.append(signed_appr)
        self.previous_digest = signed_appr["authentication"]["event_digest"]
        cycle_events.append(signed_appr)

        # 4. Execution
        self.sequence += 1
        exec_id = f"evt-{self.run_id}-exec-{self.sequence}"
        self.event_ids.add(exec_id)
        exec_body = {
            "schema_version": SCHEMA_VERSION,
            "event_id": exec_id,
            "tenant_ref": self.tenant_ref,
            "system_id": self.system_id,
            "run_id": self.run_id,
            "stream_id": self.stream_id,
            "producer_id": self.producer_id,
            "boot_id": self.boot_id,
            "sequence": self.sequence,
            "event_type": "execution.observed",
            "observed_at": now,
            "received_at": now,
            "monotonic_ns": mono_ns,
            "clock": {"clock_id": "clock-monotonic-utc", "status": "synchronized", "max_uncertainty_ms": 1.0},
            "mode": "synthetic_replay",
            "causal_refs": [appr_id],
            "provenance": {
                "adapter_name": "physical_ai_governor_adapter",
                "adapter_version": "0.1.0",
                "source_kind": "stream_socket",
                "source_digest": self.config_digest,
                "source_offsets": [self.sequence],
                "claim_class": "synthetic",
            },
            "config_digest": self.config_digest,
            "policy_digest": self.policy_digest,
            "payload": {
                "action_id": f"act-{self.sequence - 2}",
                "start": now,
                "end": now,
                "task_outcome": "success",
                "evidence_status": "synthetic",
            },
            "artifact_refs": [],
            "privacy": {"classification": "public_synthetic", "purpose_id": "cbf_safety_assurance", "retention_policy_id": "retain_30_days"},
            "previous_digest": self.previous_digest,
        }
        signed_exec = self._sign_record(exec_body, DOMAINS["EVENT"])
        validate_rbb_event(signed_exec)
        self.events.append(signed_exec)
        self.previous_digest = signed_exec["authentication"]["event_digest"]
        cycle_events.append(signed_exec)

        # Emit periodic checkpoint every 8 events
        if self.sequence % 8 == 0:
            self.create_checkpoint()

        return cycle_events

    def create_checkpoint(self) -> Dict[str, Any]:
        """Creates a signed checkpoint and witness receipt over the current event head."""
        if not self.events:
            raise RuntimeError("Cannot checkpoint empty event log")

        now = self._iso_timestamp()
        prior_cp_digest = self.checkpoints[-1]["checkpoint"]["authentication"]["event_digest"] if self.checkpoints else ZERO
        head_digest = self.events[-1]["authentication"]["event_digest"]

        cp_body = {
            "run_id": self.run_id,
            "sequence": len(self.events),
            "head_digest": head_digest,
            "previous_checkpoint_digest": prior_cp_digest,
            "created_at": now,
        }
        signed_cp = self._sign_record(
            cp_body,
            DOMAINS["CHECKPOINT"],
            key_id=self.signing_key_id,
            secret=self.signing_secret,
        )

        # Witness receipt signed by independent witness
        witness_body = {
            "run_id": self.run_id,
            "sequence": len(self.events),
            "head_digest": head_digest,
            "checkpoint_digest": signed_cp["authentication"]["event_digest"],
            "witnessed_at": now,
        }
        signed_witness = self._sign_record(
            witness_body,
            DOMAINS["WITNESS"],
            key_id=self.witness_key_id,
            secret=self.witness_secret,
        )

        cp_item = {
            "checkpoint": signed_cp,
            "receipt": signed_witness,
        }
        self.checkpoints.append(cp_item)
        return cp_item

    def close_run(self, status: str = "complete") -> Dict[str, Any]:
        """Closes the run with a final 'run.closed' event."""
        if not self.is_open or self.is_closed:
            raise RuntimeError("Recorder must be open and not already closed")

        self.sequence += 1
        now = self._iso_timestamp()
        close_id = f"evt-{self.run_id}-close"
        self.event_ids.add(close_id)

        body = {
            "schema_version": SCHEMA_VERSION,
            "event_id": close_id,
            "tenant_ref": self.tenant_ref,
            "system_id": self.system_id,
            "run_id": self.run_id,
            "stream_id": self.stream_id,
            "producer_id": self.producer_id,
            "boot_id": self.boot_id,
            "sequence": self.sequence,
            "event_type": "run.closed",
            "observed_at": now,
            "received_at": now,
            "monotonic_ns": str(time.monotonic_ns()),
            "clock": {"clock_id": "clock-monotonic-utc", "status": "synchronized", "max_uncertainty_ms": 1.0},
            "mode": "synthetic_replay",
            "causal_refs": [self.events[-1]["event_id"]],
            "provenance": {
                "adapter_name": "physical_ai_governor_adapter",
                "adapter_version": "0.1.0",
                "source_kind": "stream_socket",
                "source_digest": self.config_digest,
                "source_offsets": [self.sequence],
                "claim_class": "synthetic",
            },
            "config_digest": self.config_digest,
            "policy_digest": self.policy_digest,
            "payload": {
                "status": status,
                "event_count": self.sequence,
                "unresolved_gaps": [],
            },
            "artifact_refs": [],
            "privacy": {"classification": "public_synthetic", "purpose_id": "cbf_safety_assurance", "retention_policy_id": "retain_30_days"},
            "previous_digest": self.previous_digest,
        }

        signed_close = self._sign_record(body, DOMAINS["EVENT"])
        validate_rbb_event(signed_close)
        self.events.append(signed_close)
        self.previous_digest = signed_close["authentication"]["event_digest"]

        # Final checkpoint covering entire run
        self.create_checkpoint()

        self.is_closed = True
        return signed_close

    def export_bundle(self, output_dir: str) -> Dict[str, Any]:
        """
        Exports the entire recorded session into a portable, verifiable RBB bundle.
        Bundle structure:
            ├── manifest.json
            ├── events.ndjson
            ├── checkpoints.json
            ├── trust.json
            └── witness/
                └── latest-heads.json
        """
        if not self.is_closed:
            self.close_run()

        bundle_path = pathlib.Path(output_dir)
        bundle_path.mkdir(parents=True, exist_ok=True)
        (bundle_path / "witness").mkdir(exist_ok=True)
        (bundle_path / "objects").mkdir(exist_ok=True)

        # 1. Format events.ndjson
        events_lines = [canonical_json(e) for e in self.events]
        events_raw = "\n".join(events_lines) + "\n"
        events_bytes = events_raw.encode("utf-8")
        (bundle_path / "events.ndjson").write_bytes(events_bytes)
        events_digest = sha256_hex(events_bytes)

        # 2. Format checkpoints.json
        checkpoints_raw = canonical_json(self.checkpoints).encode("utf-8")
        (bundle_path / "checkpoints.json").write_bytes(checkpoints_raw)
        checkpoints_digest = sha256_hex(checkpoints_raw)

        # 3. Format manifest.json
        manifest_body = {
            "run_id": self.run_id,
            "tenant_ref": self.tenant_ref,
            "system_id": self.system_id,
            "schema_version": SCHEMA_VERSION,
            "event_count": len(self.events),
            "head_digest": self.previous_digest,
            "events_digest": events_digest,
            "checkpoints_digest": checkpoints_digest,
            "created_at": self._iso_timestamp(),
        }
        signed_manifest = self._sign_record(manifest_body, DOMAINS["MANIFEST"])
        (bundle_path / "manifest.json").write_bytes(canonical_json(signed_manifest).encode("utf-8"))

        # 4. Format trust.json
        trust = {
            "producers": {
                self.signing_key_id: {
                    "key_id": self.signing_key_id,
                    "algorithm": "sha256-hmac",
                    "public_key": base64.b64encode(self.signing_secret[:16]).decode("ascii"),
                    "revoked": False,
                }
            },
            "authorities": {},
            "witnesses": {
                self.witness_key_id: {
                    "key_id": self.witness_key_id,
                    "algorithm": "sha256-hmac",
                    "public_key": base64.b64encode(self.witness_secret[:16]).decode("ascii"),
                    "revoked": False,
                }
            },
        }
        (bundle_path / "trust.json").write_bytes(canonical_json(trust).encode("utf-8"))

        # 5. Format witness/latest-heads.json
        latest_head = self.checkpoints[-1]["receipt"]
        heads = {
            self.run_id: latest_head,
        }
        (bundle_path / "witness" / "latest-heads.json").write_bytes(canonical_json(heads).encode("utf-8"))

        return {
            "bundle_path": str(bundle_path.resolve()),
            "run_id": self.run_id,
            "total_events": len(self.events),
            "head_digest": self.previous_digest,
            "events_digest": events_digest,
            "checkpoints_digest": checkpoints_digest,
        }
