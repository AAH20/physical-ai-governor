"""
Robot Black Box (RBB) Offline Independent Verifier.
Complies with https://github.com/AAH20/robot-black-box verifier specification.
Performs offline, deterministic forensic audit over .rbb bundles:
    1. Canonical JSON integrity (RFC 8785)
    2. Strict SHA-256 event hash-chaining (sequence 1..N unbroken)
    3. Manifest digest consistency (events.ndjson & checkpoints.json)
    4. Causal DAG acyclicity & reference integrity
    5. Local witness consensus and latest-heads alignment
    6. External cryptographic signature authentication (fail-closed)
Pure Python 3.10+ standard library (zero external dependencies).
"""

import base64
import hashlib
import hmac
import json
import pathlib
from dataclasses import asdict, dataclass, field
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
    trust_mode: str = "AUTHENTICATED"
    is_authenticated: bool = False
    warnings: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


def _verify_hmac_sig(secret: bytes, domain: str, event_digest: str, sig_b64: str) -> bool:
    """Verifies an HMAC-SHA256 signature under domain separation in constant time."""
    domain_prefix = f"RBB-{domain}-v1\0".encode("utf-8")
    msg = domain_prefix + bytes.fromhex(event_digest)
    sig_bytes = hmac.new(secret, msg, hashlib.sha256).digest()
    expected_sig = base64.b64encode(sig_bytes * 2).decode("ascii")
    return hmac.compare_digest(sig_b64, expected_sig)


def _validate_auth_algorithm(auth: Dict[str, Any], key_id: str, trust_key_info: Optional[Dict[str, Any]] = None) -> Optional[str]:
    """
    Validates declared authentication algorithm against policy.
    Rejects algorithm confusion (e.g. labeling HMAC as ed25519) and unsupported algorithms.
    Returns error string if invalid, or None if valid.
    """
    algo = auth.get("algorithm", "")
    if not algo:
        return f"ALGORITHM_MISMATCH: Missing 'algorithm' in authentication block for key '{key_id}'"
    if algo != "sha256-hmac":
        return f"ALGORITHM_MISMATCH: Declared algorithm '{algo}' is not supported or conflicts with key policy for key '{key_id}'. Only 'sha256-hmac' is supported."
    if trust_key_info and isinstance(trust_key_info, dict):
        trust_algo = trust_key_info.get("algorithm")
        if trust_algo and trust_algo != algo:
            return f"ALGORITHM_MISMATCH: Declared algorithm '{algo}' conflicts with trust metadata '{trust_algo}' for key '{key_id}'"
    return None


class RobotBlackBoxVerifier:
    """
    Independent bundle verifier for Robot Black Box (.rbb) evidence records.
    Requires no runtime daemon, node dependencies, or remote network access.
    Implements fail-closed external authentication to prevent self-proving rewrites.
    """

    @classmethod
    def verify_bundle(
        cls,
        bundle_dir: str,
        trust_mode: str = "AUTHENTICATED",
        external_trusted_keys: Optional[Dict[str, Any]] = None,
        signing_secret: Optional[Any] = None,
        allow_self_witness: bool = False,
    ) -> RBBVerificationReport:
        """
        Audits an on-disk RBB bundle directory.

        Trust Modes:
            - "AUTHENTICATED" (default, fail-closed):
              Requires out-of-band external trusted keys. Verifies all cryptographic signatures
              on events, manifest, checkpoints, and witness receipts against external keys.
              Enforces independent witness keys (witness key != producer key).
              Fails closed if external trusted keys are missing or invalid.
            - "INTEGRITY_ONLY" (explicit opt-in):
              Audits internal structural coherence: canonical JSON, SHA-256 hash chains,
              DAG causal references, and manifest digest consistency without authenticating
              provenance against external trusted keys. Sets is_authenticated=False.
        """
        bundle_path = pathlib.Path(bundle_dir)
        checks_passed: List[str] = []
        errors: List[str] = []
        warnings: List[str] = []

        norm_mode = trust_mode.strip().upper()
        if norm_mode not in ("AUTHENTICATED", "INTEGRITY_ONLY"):
            return RBBVerificationReport(
                bundle_path=str(bundle_path),
                run_id="unknown",
                is_valid=False,
                total_events=0,
                total_checkpoints=0,
                head_digest="",
                events_digest="",
                checks_passed=[],
                errors=[f"Invalid trust_mode '{trust_mode}'. Must be 'AUTHENTICATED' or 'INTEGRITY_ONLY'."],
                trust_mode=norm_mode,
                is_authenticated=False,
                warnings=[],
            )

        # Parse external trusted keys
        trusted_producers: Dict[str, bytes] = {}
        trusted_witnesses: Dict[str, bytes] = {}
        if external_trusted_keys:
            if "producers" in external_trusted_keys or "witnesses" in external_trusted_keys:
                for k, v in external_trusted_keys.get("producers", {}).items():
                    trusted_producers[k] = v.encode("utf-8") if isinstance(v, str) else v
                for k, v in external_trusted_keys.get("witnesses", {}).items():
                    trusted_witnesses[k] = v.encode("utf-8") if isinstance(v, str) else v
            else:
                for k, v in external_trusted_keys.items():
                    sec = v.encode("utf-8") if isinstance(v, str) else v
                    trusted_producers[k] = sec
                    trusted_witnesses[k] = sec

        if signing_secret:
            sec_bytes = signing_secret.encode("utf-8") if isinstance(signing_secret, str) else signing_secret
            trusted_producers["_fallback_"] = sec_bytes

        # Fail-closed check for AUTHENTICATED mode
        if norm_mode == "AUTHENTICATED" and not trusted_producers and not trusted_witnesses:
            return RBBVerificationReport(
                bundle_path=str(bundle_path.resolve()) if bundle_path.exists() else str(bundle_path),
                run_id="unknown",
                is_valid=False,
                total_events=0,
                total_checkpoints=0,
                head_digest="",
                events_digest="",
                checks_passed=[],
                errors=[
                    "AUTHENTICATION_REQUIRED: No external trusted keys provided for AUTHENTICATED trust mode. "
                    "The bundle cannot be verified for provenance without out-of-band trusted producer/witness keys. "
                    "To verify internal hash-chain coherence only, explicitly specify trust_mode='INTEGRITY_ONLY'."
                ],
                trust_mode="AUTHENTICATED",
                is_authenticated=False,
                warnings=[],
            )

        if norm_mode == "INTEGRITY_ONLY":
            warnings.append(
                "INTEGRITY_ONLY mode: Verified internal SHA-256 hash chains, DAG causal references, "
                "and canonical JSON bodies, but provenance and signatures are NOT authenticated against external trusted keys."
            )

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
                trust_mode=norm_mode,
                is_authenticated=False,
                warnings=warnings,
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
                trust_mode=norm_mode,
                is_authenticated=False,
                warnings=warnings,
            )

        # 2. Trust Profile Verification
        producers: Dict[str, Any] = {}
        witnesses: Dict[str, Any] = {}
        try:
            trust_bytes = (bundle_path / "trust.json").read_bytes()
            trust = json.loads(trust_bytes)
            canon_trust = canonical_json(trust).encode("utf-8")
            if canon_trust != trust_bytes:
                errors.append("trust.json is not canonical RFC 8785 JSON")
            else:
                checks_passed.append("trust_canonical_json_valid")
            producers = trust.get("producers", {})
            witnesses = trust.get("witnesses", {})

            # Check independent witness rule in trust configuration
            common_keys = set(producers.keys()) & set(witnesses.keys())
            if common_keys and not allow_self_witness:
                msg = f"INDEPENDENT_WITNESS_REQUIRED: Key {common_keys} configured as both producer and witness."
                if norm_mode == "AUTHENTICATED":
                    errors.append(msg)
                else:
                    warnings.append(msg)
        except Exception as exc:
            errors.append(f"Failed parsing trust.json: {exc}")

        # 3. Manifest Verification & Body Digest Check
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

            # Recompute and verify manifest body digest
            manifest_body = {k: v for k, v in manifest.items() if k != "authentication"}
            recomputed_manifest_digest = sha256_hex(canonical_json(manifest_body).encode("utf-8"))

            manifest_auth = manifest.get("authentication")
            if not manifest_auth or not isinstance(manifest_auth, dict) or not manifest_auth.get("signature") or not manifest_auth.get("event_digest") or not manifest_auth.get("key_id"):
                errors.append(
                    "MANIFEST_AUTHENTICATION_MISSING: manifest.json is missing required authentication object with key_id, event_digest, and signature."
                )
            else:
                auth_manifest_digest = manifest_auth.get("event_digest", "")
                if recomputed_manifest_digest != auth_manifest_digest:
                    errors.append(
                        f"Manifest body digest mismatch (MANIFEST_TAMPERED): recomputed '{recomputed_manifest_digest}' != authenticated '{auth_manifest_digest}'"
                    )
                else:
                    checks_passed.append("manifest_body_digest_verified")

                m_key_id = manifest_auth.get("key_id", "")
                m_algo_err = _validate_auth_algorithm(manifest_auth, m_key_id, producers.get(m_key_id))
                if m_algo_err:
                    errors.append(f"Manifest: {m_algo_err}")

                if m_key_id in producers and producers[m_key_id].get("revoked", False):
                    errors.append(f"Manifest signed by revoked key_id: '{m_key_id}'")

                # External signature authentication
                if norm_mode == "AUTHENTICATED":
                    m_sec = trusted_producers.get(m_key_id) or trusted_producers.get("_fallback_")
                    if not m_sec:
                        errors.append(f"Manifest signed by untrusted or missing key_id: '{m_key_id}'")
                    else:
                        m_sig = manifest_auth.get("signature", "")
                        if not _verify_hmac_sig(m_sec, DOMAINS["MANIFEST"], auth_manifest_digest, m_sig):
                            errors.append("Manifest signature verification failed against external trusted key")
                        else:
                            checks_passed.append("manifest_signature_authenticated")
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
                trust_mode=norm_mode,
                is_authenticated=False,
                warnings=warnings,
            )

        # 4. Events.ndjson Raw Digest Verification
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

        # 5. Sequential Events Hash Chaining & Recomputed Body Digest Validation
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

                # Recompute event body digest (CRITICAL FORENSIC CHECK: catches payload tampering)
                evt_body = {k: v for k, v in evt.items() if k != "authentication"}
                recomputed_evt_digest = sha256_hex(canonical_json(evt_body).encode("utf-8"))
                auth = evt.get("authentication", {})
                auth_digest = auth.get("event_digest", "")

                if recomputed_evt_digest != auth_digest:
                    errors.append(
                        f"Event {i+1} body digest mismatch (BODY_TAMPERED): recomputed '{recomputed_evt_digest}' != authenticated '{auth_digest}'"
                    )

                # Key trust and revocation check
                evt_key_id = auth.get("key_id", "")
                e_algo_err = _validate_auth_algorithm(auth, evt_key_id, producers.get(evt_key_id))
                if e_algo_err:
                    errors.append(f"Event {i+1}: {e_algo_err}")

                if evt_key_id in producers and producers[evt_key_id].get("revoked", False):
                    errors.append(f"Event {i+1} signed by revoked key_id: '{evt_key_id}'")

                # Signature verification
                if norm_mode == "AUTHENTICATED":
                    e_sec = trusted_producers.get(evt_key_id) or trusted_producers.get("_fallback_")
                    if not e_sec:
                        errors.append(f"Event {i+1} signed by untrusted producer key_id: '{evt_key_id}'")
                    else:
                        e_sig = auth.get("signature", "")
                        if not _verify_hmac_sig(e_sec, DOMAINS["EVENT"], auth_digest, e_sig):
                            errors.append(f"Event {i+1} signature verification failed against external trusted key")

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
                previous_digest = auth_digest
                parsed_events.append(evt)

            except Exception as exc:
                errors.append(f"Event {i+1} validation error: {exc}")

        if not any("body digest mismatch" in err or "broken hash link" in err for err in errors):
            checks_passed.append("events_body_digests_recomputed_valid")
            checks_passed.append("events_cryptographic_hash_chain_valid")
            checks_passed.append("events_schema_conformance_valid")

        # 6. Manifest Head Digest Verification
        if previous_digest != manifest_head_digest:
            errors.append(
                f"Head digest mismatch: final event digest '{previous_digest}' != manifest head_digest '{manifest_head_digest}'"
            )
        else:
            checks_passed.append("head_digest_matched")

        # 7. Checkpoints & Witness Consensus
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
            if not isinstance(checkpoints, list):
                errors.append("checkpoints.json must contain a JSON array")
                checkpoints = []

            if norm_mode == "AUTHENTICATED" and len(checkpoints) == 0:
                errors.append(
                    "WITNESS_EVIDENCE_REQUIRED: At least one authenticated checkpoint and witness receipt is required for AUTHENTICATED trust mode."
                )

            prior_cp_digest = ZERO
            for j, cp_item in enumerate(checkpoints):
                cp = cp_item.get("checkpoint", {})
                receipt = cp_item.get("receipt", {})

                # Verify checkpoint body digest
                cp_body = {k: v for k, v in cp.items() if k != "authentication"}
                recomputed_cp_digest = sha256_hex(canonical_json(cp_body).encode("utf-8"))
                cp_auth = cp.get("authentication", {})
                cp_auth_digest = cp_auth.get("event_digest", "")
                if recomputed_cp_digest != cp_auth_digest:
                    errors.append(
                        f"Checkpoint {j+1} body digest mismatch (CHECKPOINT_TAMPERED): recomputed '{recomputed_cp_digest}' != authenticated '{cp_auth_digest}'"
                    )

                # Verify receipt body digest
                rc_body = {k: v for k, v in receipt.items() if k != "authentication"}
                recomputed_rc_digest = sha256_hex(canonical_json(rc_body).encode("utf-8"))
                rc_auth = receipt.get("authentication", {})
                rc_auth_digest = rc_auth.get("event_digest", "")
                if recomputed_rc_digest != rc_auth_digest:
                    errors.append(
                        f"Checkpoint receipt {j+1} body digest mismatch (WITNESS_TAMPERED): recomputed '{recomputed_rc_digest}' != authenticated '{rc_auth_digest}'"
                    )

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
                if receipt.get("checkpoint_digest") != cp_auth_digest:
                    errors.append(f"Checkpoint {j+1} receipt does not match checkpoint digest")

                # Check signatures in AUTHENTICATED mode
                if norm_mode == "AUTHENTICATED":
                    cp_key_id = cp_auth.get("key_id", "")
                    cp_algo_err = _validate_auth_algorithm(cp_auth, cp_key_id, producers.get(cp_key_id))
                    if cp_algo_err:
                        errors.append(f"Checkpoint {j+1}: {cp_algo_err}")

                    cp_sec = trusted_producers.get(cp_key_id) or trusted_producers.get("_fallback_")
                    if not cp_sec:
                        errors.append(f"Checkpoint {j+1} signed by untrusted producer key_id: '{cp_key_id}'")
                    else:
                        cp_sig = cp_auth.get("signature", "")
                        if not _verify_hmac_sig(cp_sec, DOMAINS["CHECKPOINT"], cp_auth_digest, cp_sig):
                            errors.append(f"Checkpoint {j+1} signature verification failed against external trusted key")

                    rc_key_id = rc_auth.get("key_id", "")
                    rc_algo_err = _validate_auth_algorithm(rc_auth, rc_key_id, witnesses.get(rc_key_id))
                    if rc_algo_err:
                        errors.append(f"Checkpoint receipt {j+1}: {rc_algo_err}")

                    # Independent witness check: witness key must not equal checkpoint producer key
                    if rc_key_id == cp_key_id and not allow_self_witness:
                        errors.append(
                            f"INDEPENDENT_WITNESS_REQUIRED: Checkpoint {j+1} receipt signed with producer key '{rc_key_id}'. "
                            "Witness must possess an independent key identity."
                        )

                    rc_sec = trusted_witnesses.get(rc_key_id) or trusted_witnesses.get("_fallback_")
                    if not rc_sec:
                        errors.append(f"Checkpoint receipt {j+1} signed by untrusted witness key_id: '{rc_key_id}'")
                    else:
                        rc_sig = rc_auth.get("signature", "")
                        if not _verify_hmac_sig(rc_sec, DOMAINS["WITNESS"], rc_auth_digest, rc_sig):
                            errors.append(f"Checkpoint receipt {j+1} witness signature verification failed against external trusted key")

                prior_cp_digest = cp_auth_digest

            if len(checkpoints) > 0 and not any("Checkpoint" in err for err in errors):
                checks_passed.append("checkpoints_chain_valid")

            # 8. Witness Latest-Heads Verification
            heads_bytes = (bundle_path / "witness" / "latest-heads.json").read_bytes()
            heads = json.loads(heads_bytes)
            if run_id not in heads:
                errors.append(f"witness/latest-heads.json missing record for run_id: {run_id}")
            else:
                head_receipt = heads[run_id]
                # Recompute head receipt body digest
                head_receipt_body = {k: v for k, v in head_receipt.items() if k != "authentication"}
                recomputed_hr_digest = sha256_hex(canonical_json(head_receipt_body).encode("utf-8"))
                hr_auth = head_receipt.get("authentication", {})
                hr_auth_digest = hr_auth.get("event_digest", "")

                if recomputed_hr_digest != hr_auth_digest:
                    errors.append("Witness latest-heads body digest mismatch (WITNESS_HEAD_TAMPERED)")

                if head_receipt.get("head_digest") != manifest_head_digest:
                    errors.append("Witness latest head_digest does not match manifest head_digest")

                # Bind latest-heads to latest checkpoint receipt
                if checkpoints:
                    last_cp_receipt = checkpoints[-1].get("receipt", {})
                    if head_receipt.get("checkpoint_digest") != last_cp_receipt.get("checkpoint_digest"):
                        errors.append("Witness latest-heads checkpoint_digest does not bind to latest checkpoint receipt")
                    if hr_auth_digest != last_cp_receipt.get("authentication", {}).get("event_digest"):
                        errors.append("Witness latest-heads receipt digest does not match latest checkpoint receipt")
                elif norm_mode == "AUTHENTICATED":
                    errors.append("WITNESS_EVIDENCE_REQUIRED: No verified checkpoint receipt available to bind witness latest-heads.")

                # In AUTHENTICATED mode, cryptographically verify the latest-head receipt signature against trusted witness
                if norm_mode == "AUTHENTICATED":
                    hr_key_id = hr_auth.get("key_id", "")
                    hr_algo_err = _validate_auth_algorithm(hr_auth, hr_key_id, witnesses.get(hr_key_id))
                    if hr_algo_err:
                        errors.append(f"Witness latest-heads: {hr_algo_err}")

                    if not hr_key_id or not hr_auth.get("signature"):
                        errors.append("Witness latest-heads receipt is missing authentication credentials")
                    else:
                        m_key_id = manifest.get("authentication", {}).get("key_id", "")
                        if hr_key_id == m_key_id and not allow_self_witness:
                            errors.append(
                                f"INDEPENDENT_WITNESS_REQUIRED: Witness latest-heads signed with producer key '{hr_key_id}'. "
                                "Witness must possess an independent key identity."
                            )

                        hr_sec = trusted_witnesses.get(hr_key_id) or trusted_witnesses.get("_fallback_")
                        if not hr_sec:
                            errors.append(f"Witness latest-heads signed by untrusted witness key_id: '{hr_key_id}'")
                        else:
                            hr_sig = hr_auth.get("signature", "")
                            if not _verify_hmac_sig(hr_sec, DOMAINS["WITNESS"], hr_auth_digest, hr_sig):
                                errors.append("Witness latest-heads signature verification failed against external trusted key (WITNESS_SIGNATURE_INVALID)")
                            elif len(checkpoints) > 0 and not any("Checkpoint" in err or "WITNESS" in err for err in errors):
                                checks_passed.append("witness_latest_heads_signature_authenticated")
                                checks_passed.append("witness_consensus_head_verified")
                                checks_passed.append("external_cryptographic_signatures_authenticated")
                else:
                    checks_passed.append("internal_witness_latest_head_matched")

        except Exception as exc:
            errors.append(f"Checkpoints/witness verification failed: {exc}")

        is_valid = (len(errors) == 0)
        is_auth = is_valid and (norm_mode == "AUTHENTICATED")

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
            trust_mode=norm_mode,
            is_authenticated=is_auth,
            warnings=warnings,
        )
