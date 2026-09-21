"""
Software Simulation of TPM 2.0 PCR Extension and Attestation Architecture.
Provides a software reference mock of hardware TPM 2.0 PCR registers and quote signing
for synthetic safety assurance and evidence packaging workflows.

CAUTION / DISCLAIMER:
This is a pure-Python software simulation designed for prototyping attestation data flows.
It does NOT communicate with physical TPM silicon (/dev/tpmrm0), ARM TrustZone, Intel SGX,
or TSS2/tpm2-tools. It does not constitute a hardware root of trust.
Zero external dependencies (pure Python standard library).
"""

import hashlib
import hmac
import os
import time
import warnings
from dataclasses import asdict, dataclass
from typing import Any, Dict, List, Optional, Tuple

from .merkle_blackbox import CompliancePassport


@dataclass
class SimulatedTPMQuote:
    """Software-simulated TPM 2.0 attestation quote."""
    pcr_bank: Dict[int, str]
    attestation_nonce: str
    quote_signature: str
    silicon_chip_id: str
    firmware_version: str
    sealed_merkle_root: str
    timestamp: float

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


# Backwards-compatible alias for existing consumers
TPMQuote = SimulatedTPMQuote


class SimulatedTPMAttestor:
    """
    Software simulation of TPM 2.0 / Secure Enclave PCR extension and quote signing.
    Simulates:
        PCR 10: SHA-256 digest of Control Barrier Function safety rules & binary code
        PCR 11: SHA-256 digest of statutory compliance policy parameters
        PCR 12: Robot chassis hardware silicon identifier mock
    """

    def __init__(
        self,
        silicon_chip_id: str = "SIMULATED-JETSON-ORIN-MOCK-01",
        hardware_endorsement_key: Optional[str] = None,
    ) -> None:
        self.chip_id = silicon_chip_id
        if hardware_endorsement_key is None:
            warnings.warn(
                "SimulatedTPMAttestor is using an insecure default test key. "
                "This is a software simulation and not a hardware root of trust.",
                UserWarning,
                stacklevel=2,
            )
            self.endorsement_key = b"INSECURE_TEST_KEY_ONLY"
        else:
            self.endorsement_key = hardware_endorsement_key.encode("utf-8")

        self.pcr_registers: Dict[int, str] = {
            10: "0" * 64,  # Code integrity
            11: "0" * 64,  # Policy limits
            12: hashlib.sha256(self.chip_id.encode()).hexdigest(),
        }

    def measure_code_integrity(self, safety_filter_source: str) -> str:
        """
        Simulates extending TPM PCR 10 with SHA-256 hash of active safety filter logic:
        PCR_new = SHA256(PCR_old || SHA256(code))
        """
        code_digest = hashlib.sha256(safety_filter_source.encode()).hexdigest()
        old_val = self.pcr_registers[10]
        new_val = hashlib.sha256(f"{old_val}:{code_digest}".encode()).hexdigest()
        self.pcr_registers[10] = new_val
        return new_val

    def measure_policy_limits(
        self,
        min_human_dist: float,
        max_torque: float,
        max_vel: float,
    ) -> str:
        """Simulates extending TPM PCR 11 with policy parameter limits."""
        policy_str = f"dist={min_human_dist}:torque={max_torque}:vel={max_vel}"
        policy_digest = hashlib.sha256(policy_str.encode()).hexdigest()
        old_val = self.pcr_registers[11]
        new_val = hashlib.sha256(f"{old_val}:{policy_digest}".encode()).hexdigest()
        self.pcr_registers[11] = new_val
        return new_val

    def seal_merkle_passport(
        self,
        passport: CompliancePassport,
        nonce: Optional[str] = None,
    ) -> SimulatedTPMQuote:
        """
        Generates a simulated TPM 2.0 Quote over the Merkle Root sealed to current PCR values.
        """
        attest_nonce = nonce or os.urandom(16).hex()
        timestamp = time.time()

        # Attestation payload = ChipID || Nonce || PCR10 || PCR11 || PCR12 || MerkleRoot || Time
        pcr_concat = ":".join(f"{k}={v}" for k, v in sorted(self.pcr_registers.items()))
        payload = f"{self.chip_id}:{attest_nonce}:{pcr_concat}:{passport.merkle_root}:{timestamp}".encode()

        # HMAC signature representing quote signature
        signature = hmac.new(self.endorsement_key, payload, hashlib.sha256).hexdigest()

        return SimulatedTPMQuote(
            pcr_bank=dict(self.pcr_registers),
            attestation_nonce=attest_nonce,
            quote_signature=signature,
            silicon_chip_id=self.chip_id,
            firmware_version="SIMULATED-JETPACK-6.2",
            sealed_merkle_root=passport.merkle_root,
            timestamp=timestamp,
        )

    def verify_tpm_quote(self, quote: SimulatedTPMQuote) -> bool:
        """
        Verifies that a simulated TPM Quote matches the expected signature.
        """
        pcr_concat = ":".join(f"{k}={v}" for k, v in sorted(quote.pcr_bank.items()))
        payload = f"{quote.silicon_chip_id}:{quote.attestation_nonce}:{pcr_concat}:{quote.sealed_merkle_root}:{quote.timestamp}".encode()
        expected_sig = hmac.new(self.endorsement_key, payload, hashlib.sha256).hexdigest()

        return hmac.compare_digest(quote.quote_signature, expected_sig)


# Backwards-compatible class alias
TPM2HardwareAttestor = SimulatedTPMAttestor
