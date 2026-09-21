"""
Robot Black Box (RBB) Offline Independent Verifier.
Complies with https://github.com/AAH20/robot-black-box verifier specification.
Performs offline, deterministic forensic audit over .rbb bundles:
    1. Canonical JSON integrity (RFC 8785)
    2. Strict SHA-256 event hash-chaining (sequence 1..N unbroken)
    3. Manifest digest consistency (events.ndjson & checkpoints.json)
    4. Causal DAG acyclicity & reference integrity
    5. Local witness consensus and latest-heads alignment
Pure Python 3.10+ standard library (zero external dependencies).
"""

import json
import pathlib
from dataclasses import asdict, dataclass
from typing import Any, Dict, List, Optional, Set

from .rbb_contract import (
    DOMAINS,
    ZERO,
    canonical_json,
    compute_rbb_digest,
    sha256_hex,
    validate_rbb_event,
)


@dataclass
class RBBVerificationReport:
    """Forensic report resulting from auditing an RBB bundle."""
    bundle_path: str
    run_id: str
    is_valid: bool
    total_events: int
    total_checkpoints: int
    head_digest: str
    events_digest: str
    checks_passed: List[str]
    errors: List[str]

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


class RobotBlackBoxVerifier:
    """
    Independent bundle verifier for Robot Black Box (.rbb) evidence records.
    Requires no runtime daemon, node dependencies, or remote network access.
    """

    @classmethod
    def verify_bundle(cls, bundle_dir: str) -> RBBVerificationReport:
        """
        Audits an on-disk RBB bundle directory.
        Returns an RBBVerificationReport with comprehensive check diagnostics.
        """
        bundle_path = pathlib.Path(bundle_dir)
        checks_passed: List[str] = []
        errors: List[str] = []

        # 1. Check directory & required files
        if not bundle_path.exists() or not bundle_path.is_dir():
            return RBBVerificationReport(
                bundle_path=str(bundle_path),
                run_id="unknown",
                is_valid=False,
                total_events=0,
                total_checkpoints=0,
                head_digest="",
                events_digest="",
                checks_passed=[],
                errors=[f"Bundle directory does not exist: {bundle_dir}"],
            )

        required_files = [
            "manifest.json",
            "events.ndjson",
            "checkpoints.json",
            "trust.json",
            "witness/latest-heads.json",
        ]
        for rf in required_files:
            fp = bundle_path / rf
            if not fp.exists():
                errors.append(f"Missing required bundle file: {rf}")

        if errors:
            return RBBVerificationReport(
                bundle_path=str(bundle_path),
                run_id="unknown",
                is_valid=False,
                total_events=0,
                total_checkpoints=0,
                head_digest="",
                events_digest="",
                checks_passed=[],
                errors=errors,
            )

        # 2. Manifest Verification
        try:
            manifest_bytes = (bundle_path / "manifest.json").read_bytes()
            manifest = json.loads(manifest_bytes)
            canon_manifest = canonical_json(manifest).encode("utf-8")
            if canon_manifest != manifest_bytes:
                errors.append("manifest.json is not canonical RFC 8785 JSON")
            else:
                checks_passed.append("manifest_canonical_json_valid")

            run_id = manifest.get("run_id", "unknown")
            expected_event_count = manifest.get("event_count", 0)
            manifest_events_digest = manifest.get("events_digest", "")
            manifest_checkpoints_digest = manifest.get("checkpoints_digest", "")
            manifest_head_digest = manifest.get("head_digest", "")
        except Exception as exc:
            errors.append(f"Failed parsing manifest.json: {exc}")
            return RBBVerificationReport(
                bundle_path=str(bundle_path),
                run_id="unknown",
                is_valid=False,
                total_events=0,
                total_checkpoints=0,
                head_digest="",
                events_digest="",
                checks_passed=checks_passed,
                errors=errors,
            )

        # 3. Events.ndjson Raw Digest Verification
        events_bytes = (bundle_path / "events.ndjson").read_bytes()
        actual_events_digest = sha256_hex(events_bytes)
        if actual_events_digest != manifest_events_digest:
            errors.append(
                f"events.ndjson SHA-256 digest mismatch. Actual: {actual_events_digest}, Manifest: {manifest_events_digest}"
            )
        else:
            checks_passed.append("events_ndjson_digest_matched")

        if not events_bytes.endswith(b"\n"):
            errors.append("events.ndjson does not terminate with trailing newline")
        else:
            checks_passed.append("events_ndjson_trailing_newline_valid")

        # 4. Sequential Events Hash Chaining & Schema Validation
        lines = [line for line in events_bytes.splitlines() if line.strip()]
        if len(lines) != expected_event_count:
            errors.append(f"Event count mismatch: expected {expected_event_count}, found {len(lines)}")
        else:
            checks_passed.append("event_count_matched")

        previous_digest = ZERO
        seen_event_ids: Set[str] = set()
        parsed_events: List[Dict[str, Any]] = []

        for i, line in enumerate(lines):
            try:
                evt = json.loads(line)
                canon_line = canonical_json(evt).encode("utf-8")
                if canon_line != line:
                    errors.append(f"Event {i+1} line is not canonical RFC 8785 JSON")

                # Schema validation
                validate_rbb_event(evt)

                # Sequence check
                if evt.get("sequence") != i + 1:
                    errors.append(f"Event sequence out of order: expected {i+1}, got {evt.get('sequence')}")

                # Hash chaining check
                if evt.get("previous_digest") != previous_digest:
                    errors.append(
                        f"Event {i+1} broken hash link: previous_digest '{evt.get('previous_digest')}' != expected '{previous_digest}'"
                    )

                # Causal reference check
                for ref in evt.get("causal_refs", []):
                    if ref not in seen_event_ids:
                        errors.append(f"Event {i+1} references unknown causal event_id: '{ref}'")

                # Run ID check
                if evt.get("run_id") != run_id:
                    errors.append(f"Event {i+1} run_id '{evt.get('run_id')}' != manifest run_id '{run_id}'")

                seen_event_ids.add(evt["event_id"])
                previous_digest = evt["authentication"]["event_digest"]
                parsed_events.append(evt)

            except Exception as exc:
                errors.append(f"Event {i+1} validation error: {exc}")

        if not errors:
            checks_passed.append("events_cryptographic_hash_chain_valid")
            checks_passed.append("events_schema_conformance_valid")

        # 5. Manifest Head Digest Verification
        if previous_digest != manifest_head_digest:
            errors.append(
                f"Head digest mismatch: final event digest '{previous_digest}' != manifest head_digest '{manifest_head_digest}'"
            )
        else:
            checks_passed.append("head_digest_matched")

        # 6. Checkpoints & Witness Consensus
        try:
            cp_bytes = (bundle_path / "checkpoints.json").read_bytes()
            actual_cp_digest = sha256_hex(cp_bytes)
            if actual_cp_digest != manifest_checkpoints_digest:
                errors.append(
                    f"checkpoints.json digest mismatch. Actual: {actual_cp_digest}, Manifest: {manifest_checkpoints_digest}"
                )
            else:
                checks_passed.append("checkpoints_json_digest_matched")

            checkpoints = json.loads(cp_bytes)
            prior_cp_digest = ZERO
            for j, cp_item in enumerate(checkpoints):
                cp = cp_item.get("checkpoint", {})
                receipt = cp_item.get("receipt", {})

                # Check previous checkpoint link
                if cp.get("previous_checkpoint_digest") != prior_cp_digest:
                    errors.append(f"Checkpoint {j+1} broken link to prior checkpoint")

                # Check head digest matches event at sequence
                cp_seq = cp.get("sequence", 0)
                if cp_seq <= len(parsed_events):
                    expected_event_head = parsed_events[cp_seq - 1]["authentication"]["event_digest"]
                    if cp.get("head_digest") != expected_event_head:
                        errors.append(f"Checkpoint {j+1} head_digest does not match event sequence {cp_seq}")

                # Receipt alignment
                if receipt.get("checkpoint_digest") != cp["authentication"]["event_digest"]:
                    errors.append(f"Checkpoint {j+1} receipt does not match checkpoint digest")

                prior_cp_digest = cp["authentication"]["event_digest"]

            if not errors:
                checks_passed.append("checkpoints_chain_valid")

            # 7. Witness Latest-Heads Verification
            heads_bytes = (bundle_path / "witness" / "latest-heads.json").read_bytes()
            heads = json.loads(heads_bytes)
            if run_id not in heads:
                errors.append(f"witness/latest-heads.json missing record for run_id: {run_id}")
            else:
                head_receipt = heads[run_id]
                if head_receipt.get("head_digest") != manifest_head_digest:
                    errors.append("Witness latest head_digest does not match manifest head_digest")
                else:
                    checks_passed.append("witness_consensus_head_verified")

        except Exception as exc:
            errors.append(f"Checkpoints/witness verification failed: {exc}")

        is_valid = (len(errors) == 0)
        return RBBVerificationReport(
            bundle_path=str(bundle_path.resolve()),
            run_id=run_id,
            is_valid=is_valid,
            total_events=len(parsed_events),
            total_checkpoints=len(checkpoints) if "checkpoints" in locals() else 0,
            head_digest=manifest_head_digest,
            events_digest=actual_events_digest,
            checks_passed=checks_passed,
            errors=errors,
        )
