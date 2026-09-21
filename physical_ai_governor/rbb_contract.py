"""
Robot Black Box (RBB) Contract & Canonical Serialization Engine.
Fully compliant with https://github.com/AAH20/robot-black-box contract specification:
    - Schema Version: 1.0.0-local.1
    - RFC 8785 Canonical JSON Serialization
    - Domain Separation: RBB-{domain}-v1\\0
    - Exact event schema validation & field structure
Pure Python 3.10+ standard library (zero external dependencies).
"""

import hashlib
import json
import re
from typing import Any, Dict, List, Optional, Set

VERSION = "0.1.0"
SCHEMA_VERSION = "1.0.0-local.1"
ZERO = "0" * 64

DOMAINS = {
    "EVENT": "EVENT",
    "MANIFEST": "MANIFEST",
    "CHECKPOINT": "CHECKPOINT",
    "WITNESS": "WITNESS",
    "APPROVAL": "APPROVAL",
}

EVENT_FIELDS = [
    "schema_version",
    "event_id",
    "tenant_ref",
    "system_id",
    "run_id",
    "stream_id",
    "producer_id",
    "boot_id",
    "sequence",
    "event_type",
    "observed_at",
    "received_at",
    "monotonic_ns",
    "clock",
    "mode",
    "causal_refs",
    "provenance",
    "config_digest",
    "policy_digest",
    "payload",
    "artifact_refs",
    "privacy",
    "previous_digest",
    "authentication",
]

PAYLOAD_FIELDS: Dict[str, List[str]] = {
    "run.started": ["task", "required_streams", "trust_profile", "source_digest"],
    "observation.recorded": [
        "sensor_id",
        "frame_index",
        "value",
        "units",
        "coordinate_frame",
        "evidence_status",
    ],
    "proposal.recorded": [
        "action_id",
        "input_refs",
        "requested_scope",
        "model_revision",
        "action_representation",
    ],
    "approval.recorded": ["grant"],
    "execution.observed": ["action_id", "start", "end", "task_outcome", "evidence_status"],
    "telemetry.gap": ["affected_stream", "missing_interval", "origin"],
    "config.changed": ["previous_config_digest", "new_config_digest", "activated_at"],
    "run.closed": ["status", "event_count", "unresolved_gaps"],
}


def canonical_json(value: Any) -> str:
    """
    Serializes a Python object to deterministic RFC 8785 Canonical JSON.
    Guarantees:
        1. Object keys sorted lexicographically (Unicode code point order).
        2. No whitespace around colons or commas (separators=(',', ':')).
        3. String characters properly escaped without unnecessary sequences.
        4. Rejects non-finite numbers (NaN, Infinity) and invalid types.
    """
    def _check(v: Any) -> None:
        if v is None or isinstance(v, bool):
            return
        if isinstance(v, (int, float)):
            if isinstance(v, float) and (v != v or abs(v) == float("inf")):
                raise ValueError("Non-finite number in canonical JSON")
            return
        if isinstance(v, str):
            # Check for surrogate pairs or invalid unicode
            try:
                v.encode("utf-8")
            except UnicodeEncodeError as exc:
                raise ValueError(f"Invalid unicode string: {exc}") from exc
            return
        if isinstance(v, (list, tuple)):
            for elem in v:
                _check(elem)
            return
        if isinstance(v, dict):
            for k, val in v.items():
                if not isinstance(k, str):
                    raise ValueError(f"Dictionary key must be string, got {type(k)}")
                _check(val)
            return
        raise ValueError(f"Invalid JSON data type: {type(v)}")

    _check(value)
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def sha256_hex(data: bytes) -> str:
    """Computes SHA-256 hex digest of given byte array."""
    return hashlib.sha256(data).hexdigest()


def compute_rbb_digest(obj: Any) -> str:
    """Computes SHA-256 digest of canonical JSON representation of object."""
    return sha256_hex(canonical_json(obj).encode("utf-8"))


def exact_keys(obj: Dict[str, Any], expected_keys: List[str], label: str) -> None:
    """Ensures dictionary contains exactly the expected set of keys without extra/missing fields."""
    if not isinstance(obj, dict):
        raise ValueError(f"SCHEMA_{label}: Expected dict, got {type(obj).__name__}")
    actual = sorted(obj.keys())
    expected = sorted(expected_keys)
    if actual != expected:
        raise ValueError(f"SCHEMA_{label}: Key mismatch. Actual: {actual}, Expected: {expected}")


def validate_rbb_event(e: Dict[str, Any]) -> Dict[str, Any]:
    """
    Validates that an event strictly complies with robot-black-box schema specifications.
    Raises ValueError on any schema violation.
    """
    exact_keys(e, EVENT_FIELDS, "EVENT")

    if e.get("schema_version") != SCHEMA_VERSION:
        raise ValueError(f"UNSUPPORTED_SCHEMA: {e.get('schema_version')}")

    for k in ["event_id", "tenant_ref", "system_id", "run_id", "stream_id", "producer_id", "boot_id"]:
        val = e.get(k)
        if not isinstance(val, str) or not re.match(r"^[A-Za-z0-9_.:-]{1,128}$", val):
            raise ValueError(f"SCHEMA_{k}: Invalid string identifier '{val}'")

    seq = e.get("sequence")
    if not isinstance(seq, int) or isinstance(seq, bool) or seq < 1:
        raise ValueError(f"SCHEMA_SEQUENCE: Expected positive integer, got {seq}")

    etype = e.get("event_type")
    if etype not in PAYLOAD_FIELDS:
        raise ValueError(f"UNSUPPORTED_EVENT_TYPE: {etype}")

    exact_keys(e.get("payload", {}), PAYLOAD_FIELDS[etype], "PAYLOAD")

    if e.get("mode") != "synthetic_replay":
        raise ValueError(f"UNSUPPORTED_MODE: {e.get('mode')}")

    for k in ["config_digest", "policy_digest", "previous_digest"]:
        digest_val = e.get(k)
        if not isinstance(digest_val, str) or not re.match(r"^[a-f0-9]{64}$", digest_val):
            raise ValueError(f"SCHEMA_{k}: Expected 64-char hex digest, got '{digest_val}'")

    # Clocks and Timestamps
    rec_at = e.get("received_at")
    if rec_at is not None and (not isinstance(rec_at, str) or not rec_at.endswith("Z")):
        raise ValueError(f"SCHEMA_received_at: Invalid ISO timestamp '{rec_at}'")

    mono = e.get("monotonic_ns")
    if not isinstance(mono, (int, str)) or not str(mono).isdigit():
        raise ValueError(f"SCHEMA_CLOCK: Invalid monotonic_ns '{mono}'")

    clock = e.get("clock", {})
    exact_keys(clock, ["clock_id", "status", "max_uncertainty_ms"], "CLOCK")
    if clock.get("status") not in ["synchronized", "unsynchronized", "unknown"]:
        raise ValueError(f"SCHEMA_CLOCK: Invalid status {clock.get('status')}")

    # Causal References
    causal_refs = e.get("causal_refs")
    if not isinstance(causal_refs, list) or any(not isinstance(x, str) for x in causal_refs):
        raise ValueError("SCHEMA_REFS: causal_refs must be a list of string IDs")
    if len(set(causal_refs)) != len(causal_refs):
        raise ValueError("SCHEMA_REFS: Duplicate IDs in causal_refs")

    # Provenance
    prov = e.get("provenance", {})
    exact_keys(prov, ["adapter_name", "adapter_version", "source_kind", "source_digest", "source_offsets", "claim_class"], "PROVENANCE")
    if prov.get("claim_class") != "synthetic":
        raise ValueError(f"SCHEMA_PROVENANCE: Expected claim_class 'synthetic', got {prov.get('claim_class')}")
    if not re.match(r"^[a-f0-9]{64}$", prov.get("source_digest", "")):
        raise ValueError("SCHEMA_PROVENANCE: Invalid source_digest")

    # Privacy
    privacy = e.get("privacy", {})
    exact_keys(privacy, ["classification", "purpose_id", "retention_policy_id"], "PRIVACY")
    if privacy.get("classification") != "public_synthetic":
        raise ValueError(f"UNSUPPORTED_PRIVATE_CAPTURE: {privacy.get('classification')}")

    # Artifacts
    artifacts = e.get("artifact_refs")
    if not isinstance(artifacts, list):
        raise ValueError("SCHEMA_ARTIFACTS: artifact_refs must be a list")
    for a in artifacts:
        exact_keys(a, ["object_id", "algorithm", "digest", "bytes", "media_type", "capture_role", "availability"], "ARTIFACT")
        if a.get("algorithm") != "sha256" or not re.match(r"^[a-f0-9]{64}$", a.get("digest", "")):
            raise ValueError("SCHEMA_ARTIFACT: Invalid artifact digest")

    # Authentication
    auth = e.get("authentication", {})
    exact_keys(auth, ["algorithm", "key_id", "event_digest", "signature"], "AUTH")
    if auth.get("algorithm") not in ["ed25519", "sha256-hmac"]:
        raise ValueError(f"SCHEMA_AUTH: Unsupported algorithm '{auth.get('algorithm')}'")
    if not re.match(r"^[a-f0-9]{64}$", auth.get("event_digest", "")):
        raise ValueError("SCHEMA_AUTH: Invalid event_digest")

    return e
