"""Attacker device and client entropy fingerprinting for Expose Shield (Phase 35)."""

import hashlib
from typing import Dict, Optional
from pydantic import BaseModel


class ClientFingerprint(BaseModel):
    """Normalized client identity and device entropy signature."""
    client_ip: str
    device_hash: str
    entropy_summary: str
    user_agent: str


class AttackerFingerprinter:
    """Computes stable hardware, browser, and entropy fingerprints for clients."""

    @staticmethod
    def fingerprint(
        client_ip: str,
        headers: Dict[str, str],
    ) -> ClientFingerprint:
        """Derives a deterministic device hash from client HTTP attributes."""
        # Normalize header keys to lowercase
        norm_headers = {k.lower(): v for k, v in headers.items()}

        ua = norm_headers.get("user-agent", "unknown")
        accept = norm_headers.get("accept", "*/*")
        accept_lang = norm_headers.get("accept-language", "")
        accept_enc = norm_headers.get("accept-encoding", "")
        sec_ch_ua = norm_headers.get("sec-ch-ua", "")
        sec_ch_platform = norm_headers.get("sec-ch-ua-platform", "")

        # Entropy vector components
        components = [
            ua.strip(),
            accept.strip(),
            accept_lang.strip(),
            accept_enc.strip(),
            sec_ch_ua.strip(),
            sec_ch_platform.strip(),
        ]
        raw_entropy = "|".join(components)
        device_hash = hashlib.sha256(raw_entropy.encode("utf-8")).hexdigest()[:20]

        summary = f"IP: {client_ip} | UA: {ua[:40]} | Platform: {sec_ch_platform or 'N/A'}"

        return ClientFingerprint(
            client_ip=client_ip,
            device_hash=device_hash,
            entropy_summary=summary,
            user_agent=ua,
        )
