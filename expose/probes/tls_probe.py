"""TLS and cryptographic posture probe for Expose.

Performs socket-level TLS handshakes, certificate chain inspection, protocol deprecation
checks, and cipher suite evaluation.
"""

import asyncio
from datetime import datetime, timezone
import fnmatch
import socket
import ssl
from typing import Any, Dict, List, Optional

from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa, ec, dsa
from cryptography.x509.oid import ExtensionOID, NameOID

from expose.core.models import (
    Category,
    Confidence,
    Evidence,
    EvidenceType,
    Finding,
    ObservationStatus,
    Severity,
    TargetScope,
)
from .base import BaseProbe


# Common weak cipher strings to probe
WEAK_CIPHER_PROFILES = [
    ("NULL", "NULL Ciphers (No Encryption)", "eNULL:aNULL", Severity.CRITICAL, "CWE-327", "NULL ciphers transmit all network traffic in plaintext."),
    ("RC4", "Insecure RC4 Cipher Suite Supported", "RC4", Severity.HIGH, "CWE-327", "RC4 suffers from multiple cryptographic biases (Bar Mitzvah attack) allowing plaintext recovery."),
    ("3DES_SWEET32", "Insecure 3DES / 64-bit Block Cipher Supported (SWEET32)", "3DES:DES-CBC3-SHA:EDH-RSA-DES-CBC3-SHA", Severity.MEDIUM, "CWE-326", "3DES 64-bit block size enables SWEET32 collision attacks (CVE-2016-2183) against long-lived sessions."),
    ("EXPORT", "Insecure EXPORT-Grade Cipher Suite Supported (FREAK/Logjam)", "EXPORT:EXP", Severity.HIGH, "CWE-327", "Export-grade ciphers use deliberately weakened 40/56-bit keys breakable in real time."),
]


class TLSProbe(BaseProbe):
    """Inspects TLS/SSL configuration, certificate validity, SANs, protocols, and ciphers."""

    @property
    def name(self) -> str:
        return "tls_posture"

    @property
    def category(self) -> Category:
        return Category.CRYPTOGRAPHY

    @property
    def description(self) -> str:
        return "Validates TLS certificates, expiration, SAN coverage, protocol versions, and cipher suites."

    async def execute(self, target: TargetScope) -> List[Finding]:
        port = target.port if target.port != 80 else 443

        loop = asyncio.get_running_loop()
        try:
            findings = await loop.run_in_executor(None, self._inspect_tls, target, port)
            return findings
        except Exception as e:
            if target.scheme == "https":
                evidence = Evidence(
                    type=EvidenceType.RAW_SOCKET,
                    summary=f"TLS handshake failed on {target.host}:{port}: {str(e)}",
                    raw_data={"host": target.host, "port": port, "error": str(e)}
                )
                return [
                    self.create_finding(
                        target=target,
                        title="TLS Handshake Failed or Port Unreachable",
                        severity=Severity.HIGH,
                        confidence=Confidence.CONFIRMED,
                        status=ObservationStatus.CONFIRMED,
                        description=f"Failed to establish a secure TLS connection with '{target.host}:{port}'. Details: {str(e)}",
                        impact_explanation="Traffic cannot be encrypted; browsers and API clients will refuse to connect over HTTPS.",
                        remediation="Ensure port 443 is accessible and valid TLS certificates are configured.",
                        verification_command=f"openssl s_client -connect {target.host}:{port} -servername {target.host}",
                        evidence=evidence,
                        category=Category.TRANSPORT_SECURITY,
                        cwe_id="CWE-295"
                    )
                ]
            return []

    def _inspect_tls(self, target: TargetScope, port: int) -> List[Finding]:
        findings: List[Finding] = []
        host = target.host

        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE

        raw_cert_bytes: Optional[bytes] = None
        negotiated_protocol: Optional[str] = None
        negotiated_cipher: Optional[tuple] = None

        with socket.create_connection((host, port), timeout=5.0) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                raw_cert_bytes = ssock.getpeercert(binary_form=True)
                negotiated_protocol = ssock.version()
                negotiated_cipher = ssock.cipher()

        if not raw_cert_bytes:
            return findings

        cert = x509.load_der_x509_certificate(raw_cert_bytes, default_backend())

        now = datetime.now(timezone.utc)
        not_valid_before = cert.not_valid_before_utc
        not_valid_after = cert.not_valid_after_utc
        sig_algo = cert.signature_algorithm_oid._name

        subject_cn = self._get_common_name(cert.subject)
        issuer_cn = self._get_common_name(cert.issuer)
        san_names = self._get_san_names(cert)

        cert_metadata: Dict[str, Any] = {
            "subject": subject_cn,
            "issuer": issuer_cn,
            "not_valid_before": not_valid_before.isoformat(),
            "not_valid_after": not_valid_after.isoformat(),
            "signature_algorithm": sig_algo,
            "san_names": san_names,
            "negotiated_protocol": negotiated_protocol,
            "negotiated_cipher": negotiated_cipher,
        }

        # Check A: Certificate Expiration
        days_remaining = (not_valid_after - now).total_seconds() / 86400.0
        if days_remaining < 0:
            evidence = Evidence(
                type=EvidenceType.CERTIFICATE_METADATA,
                summary=f"Certificate expired on {not_valid_after.isoformat()} ({abs(int(days_remaining))} days ago).",
                raw_data=cert_metadata
            )
            findings.append(
                self.create_finding(
                    target=target,
                    title="Expired SSL/TLS Certificate",
                    severity=Severity.CRITICAL,
                    confidence=Confidence.CONFIRMED,
                    status=ObservationStatus.CONFIRMED,
                    description=f"The TLS certificate for '{host}' expired on {not_valid_after.strftime('%Y-%m-%d %H:%M:%S UTC')}.",
                    impact_explanation="Browsers block access with prominent interstitial warnings; automated clients and webhooks fail immediately.",
                    remediation="Renew and deploy an updated certificate immediately.",
                    verification_command=f"openssl s_client -connect {host}:{port} -servername {host} 2>&1 | openssl x509 -noout -dates",
                    evidence=evidence,
                    category=Category.CRYPTOGRAPHY,
                    cwe_id="CWE-295"
                )
            )
        elif days_remaining <= 14:
            evidence = Evidence(
                type=EvidenceType.CERTIFICATE_METADATA,
                summary=f"Certificate expires in {days_remaining:.1f} days.",
                raw_data=cert_metadata
            )
            findings.append(
                self.create_finding(
                    target=target,
                    title="SSL/TLS Certificate Expiring Soon",
                    severity=Severity.MEDIUM,
                    confidence=Confidence.CONFIRMED,
                    status=ObservationStatus.CONFIRMED,
                    description=f"The TLS certificate for '{host}' will expire in {days_remaining:.1f} days.",
                    impact_explanation="Failure to renew in time will lead to service outage and trust warnings for all visitors.",
                    remediation="Initiate certificate renewal and ensure automated renewal mechanisms (e.g. Certbot) are healthy.",
                    verification_command=f"openssl s_client -connect {host}:{port} -servername {host} 2>&1 | openssl x509 -noout -enddate",
                    evidence=evidence,
                    category=Category.CRYPTOGRAPHY,
                    cwe_id="CWE-295"
                )
            )
        else:
            # Positive observation
            evidence = Evidence(
                type=EvidenceType.CERTIFICATE_METADATA,
                summary=f"Valid TLS certificate issued by '{issuer_cn}' ({int(days_remaining)} days remaining).",
                raw_data=cert_metadata
            )
            findings.append(
                self.create_finding(
                    target=target,
                    title="Valid SSL/TLS Certificate",
                    severity=Severity.INFO,
                    confidence=Confidence.CONFIRMED,
                    status=ObservationStatus.OBSERVED,
                    description=f"Certificate presented by '{host}' is valid until {not_valid_after.strftime('%Y-%m-%d')} ({int(days_remaining)} days remaining).",
                    impact_explanation="Ensures encrypted communication and standard trust validation across all user agents.",
                    remediation="Maintain certificate lifecycle management.",
                    verification_command=f"openssl s_client -connect {host}:{port} -servername {host} 2>&1 | openssl x509 -noout -dates",
                    evidence=evidence,
                    category=Category.CRYPTOGRAPHY
                )
            )

        # Check B: SAN match
        host_matched = any(fnmatch.fnmatch(host.lower(), san.lower()) for san in san_names)
        if not host_matched:
            evidence = Evidence(
                type=EvidenceType.CERTIFICATE_METADATA,
                summary=f"Host '{host}' does not match any SAN: {san_names}",
                raw_data=cert_metadata
            )
            findings.append(
                self.create_finding(
                    target=target,
                    title="SSL/TLS Certificate Name Mismatch",
                    severity=Severity.HIGH,
                    confidence=Confidence.CONFIRMED,
                    status=ObservationStatus.CONFIRMED,
                    description=f"The certificate does not cover hostname '{host}'. Listed SANs: {', '.join(san_names) or 'None'}.",
                    impact_explanation="Clients will fail hostname verification, presenting SSL security warnings.",
                    remediation="Reissue certificate including this domain in Subject Alternative Names.",
                    verification_command=f"openssl s_client -connect {host}:{port} -servername {host} 2>&1 | openssl x509 -noout -text | grep -A1 'Subject Alternative Name'",
                    evidence=evidence,
                    category=Category.CRYPTOGRAPHY,
                    cwe_id="CWE-297"
                )
            )

        # Check C: Self-Signed Certificate
        if cert.issuer == cert.subject:
            evidence = Evidence(
                type=EvidenceType.CERTIFICATE_METADATA,
                summary=f"Certificate issuer matches subject ({subject_cn}).",
                raw_data=cert_metadata
            )
            findings.append(
                self.create_finding(
                    target=target,
                    title="Self-Signed SSL/TLS Certificate in Use",
                    severity=Severity.HIGH,
                    confidence=Confidence.CONFIRMED,
                    status=ObservationStatus.CONFIRMED,
                    description=f"The certificate is self-signed (Issuer and Subject: '{subject_cn}').",
                    impact_explanation="Cannot be verified against public Root CAs; untrusted by default in all web browsers.",
                    remediation="Deploy a certificate issued by an ACME/public CA such as Let's Encrypt.",
                    verification_command=f"openssl s_client -connect {host}:{port} -servername {host} 2>&1 | openssl x509 -noout -issuer -subject",
                    evidence=evidence,
                    category=Category.CRYPTOGRAPHY,
                    cwe_id="CWE-295"
                )
            )

        # Check D: Protocol Deprecation
        deprecated_protocols = self._test_deprecated_protocols(host, port)
        if deprecated_protocols:
            evidence = Evidence(
                type=EvidenceType.TLS_HANDSHAKE,
                summary=f"Server completed handshakes with deprecated protocol(s): {', '.join(deprecated_protocols)}",
                raw_data={"host": host, "port": port, "supported_deprecated_protocols": deprecated_protocols}
            )
            findings.append(
                self.create_finding(
                    target=target,
                    title="Deprecated TLS Protocol Version Supported",
                    severity=Severity.HIGH,
                    confidence=Confidence.CONFIRMED,
                    status=ObservationStatus.CONFIRMED,
                    description=f"The server '{host}:{port}' supports deprecated TLS protocols: {', '.join(deprecated_protocols)}.",
                    impact_explanation="Exposes connections to legacy cryptographic downgrade attacks (e.g. POODLE, BEAST).",
                    remediation="Disable TLS 1.0 and 1.1. Enforce TLS 1.2 and TLS 1.3.",
                    verification_command=f"openssl s_client -connect {host}:{port} -tls1_1",
                    evidence=evidence,
                    category=Category.TRANSPORT_SECURITY,
                    cwe_id="CWE-326"
                )
            )
        else:
            # Positive observation of modern TLS negotiation
            evidence = Evidence(
                type=EvidenceType.TLS_HANDSHAKE,
                summary=f"Negotiated modern protocol: {negotiated_protocol} with cipher: {negotiated_cipher[0] if negotiated_cipher else 'unknown'}",
                raw_data={"protocol": negotiated_protocol, "cipher": negotiated_cipher}
            )
            findings.append(
                self.create_finding(
                    target=target,
                    title=f"Modern TLS Protocol Negotiated ({negotiated_protocol})",
                    severity=Severity.INFO,
                    confidence=Confidence.CONFIRMED,
                    status=ObservationStatus.OBSERVED,
                    description=f"Server successfully established secure handshake using {negotiated_protocol}.",
                    impact_explanation="Provides strong forward secrecy and protects traffic from passive decryption.",
                    remediation="Keep TLS configurations updated as cryptographic standards evolve.",
                    verification_command=f"openssl s_client -connect {host}:{port} -servername {host}",
                    evidence=evidence,
                    category=Category.TRANSPORT_SECURITY
                )
            )

        # Check E: Key Length and Signature Algorithm
        public_key = cert.public_key()
        if isinstance(public_key, rsa.RSAPublicKey):
            key_size = public_key.key_size
            cert_metadata["key_type"] = "RSA"
            cert_metadata["key_size"] = key_size
            if key_size < 2048:
                evidence = Evidence(
                    type=EvidenceType.CERTIFICATE_METADATA,
                    summary=f"Insecure RSA key size: {key_size} bits (minimum required: 2048 bits).",
                    raw_data=cert_metadata
                )
                findings.append(
                    self.create_finding(
                        target=target,
                        title="Weak RSA Key Size in SSL/TLS Certificate (< 2048 bits)",
                        severity=Severity.HIGH,
                        confidence=Confidence.CONFIRMED,
                        status=ObservationStatus.CONFIRMED,
                        description=f"The certificate uses an RSA key size of only {key_size} bits, which is vulnerable to factorization.",
                        impact_explanation="Inadequate key lengths can be factored by state-level adversaries or cloud compute clusters to forge certificates or decrypt traffic.",
                        remediation="Reissue the certificate with an RSA key size of at least 2048 bits (or ECDSA with P-256).",
                        verification_command=f"openssl s_client -connect {host}:{port} -servername {host} 2>&1 | openssl x509 -noout -text | grep 'Public-Key:'",
                        evidence=evidence,
                        category=Category.CRYPTOGRAPHY,
                        cwe_id="CWE-326"
                    )
                )
        elif isinstance(public_key, ec.EllipticCurvePublicKey):
            cert_metadata["key_type"] = "ECDSA"
            cert_metadata["curve"] = public_key.curve.name

        # Insecure Signature Algorithm (SHA-1, MD5)
        if "sha1" in sig_algo.lower() or "md5" in sig_algo.lower():
            evidence = Evidence(
                type=EvidenceType.CERTIFICATE_METADATA,
                summary=f"Obsolete certificate signature algorithm: {sig_algo}",
                raw_data=cert_metadata
            )
            findings.append(
                self.create_finding(
                    target=target,
                    title="Obsolete/Insecure Certificate Signature Algorithm",
                    severity=Severity.HIGH,
                    confidence=Confidence.CONFIRMED,
                    status=ObservationStatus.CONFIRMED,
                    description=f"The certificate is signed with '{sig_algo}', which has known collision weaknesses.",
                    impact_explanation="Cryptographic collisions allow attackers to forge valid certificates signed by trusted authorities.",
                    remediation="Reissue certificate using SHA-256 or SHA-384.",
                    verification_command=f"openssl s_client -connect {host}:{port} -servername {host} 2>&1 | openssl x509 -noout -text | grep 'Signature Algorithm:'",
                    evidence=evidence,
                    category=Category.CRYPTOGRAPHY,
                    cwe_id="CWE-327"
                )
            )

        # Check F: Weak Cipher Suites Handshake Audit
        weak_cipher_findings = self._test_weak_ciphers(target, host, port)
        findings.extend(weak_cipher_findings)

        # Check G: Forward Secrecy (PFS) in Negotiated Cipher
        if negotiated_cipher and len(negotiated_cipher) > 0:
            cipher_name = negotiated_cipher[0].upper()
            has_pfs = any(k in cipher_name for k in ("ECDHE", "DHE", "CHACHA20", "GCM"))
            if not has_pfs and negotiated_protocol in ("TLSv1.2", "TLSv1.3"):
                evidence = Evidence(
                    type=EvidenceType.TLS_HANDSHAKE,
                    summary=f"Negotiated cipher '{cipher_name}' lacks Ephemeral Diffie-Hellman Forward Secrecy (PFS).",
                    raw_data={"negotiated_cipher": negotiated_cipher, "protocol": negotiated_protocol}
                )
                findings.append(
                    self.create_finding(
                        target=target,
                        title="Cipher Suite Lacks Perfect Forward Secrecy (PFS)",
                        severity=Severity.LOW,
                        confidence=Confidence.CONFIRMED,
                        status=ObservationStatus.CONFIRMED,
                        description=f"The server negotiated static key exchange '{cipher_name}' without Forward Secrecy.",
                        impact_explanation="If the server's private key is compromised in the future, past recorded sessions can be decrypted retrospectively.",
                        remediation="Prioritize ECDHE/DHE cipher suites (e.g. ECDHE-ECDSA-AES128-GCM-SHA256, ECDHE-RSA-AES256-GCM-SHA384).",
                        verification_command=f"openssl s_client -connect {host}:{port} -servername {host} | grep 'Cipher'",
                        evidence=evidence,
                        category=Category.CRYPTOGRAPHY,
                        cwe_id="CWE-326"
                    )
                )

        return findings

    def _get_common_name(self, name: x509.Name) -> str:
        cns = name.get_attributes_for_oid(NameOID.COMMON_NAME)
        if cns:
            return cns[0].value
        return ""

    def _get_san_names(self, cert: x509.Certificate) -> List[str]:
        names = []
        try:
            san_ext = cert.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
            for name in san_ext.value:
                names.append(str(name.value))
        except Exception:
            pass
        return names

    def _test_deprecated_protocols(self, host: str, port: int) -> List[str]:
        supported = []
        if hasattr(ssl, "PROTOCOL_TLSv1"):
            try:
                ctx = ssl.SSLContext(ssl.PROTOCOL_TLSv1)
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE
                with socket.create_connection((host, port), timeout=3.0) as s:
                    with ctx.wrap_socket(s, server_hostname=host):
                        supported.append("TLSv1.0")
            except Exception:
                pass

        if hasattr(ssl, "PROTOCOL_TLSv1_1"):
            try:
                ctx = ssl.SSLContext(ssl.PROTOCOL_TLSv1_1)
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE
                with socket.create_connection((host, port), timeout=3.0) as s:
                    with ctx.wrap_socket(s, server_hostname=host):
                        supported.append("TLSv1.1")
            except Exception:
                pass

        return supported

    def _test_weak_ciphers(self, target: TargetScope, host: str, port: int) -> List[Finding]:
        findings: List[Finding] = []
        for profile_key, title, ciphers_str, sev, cwe, explanation in WEAK_CIPHER_PROFILES:
            try:
                ctx = ssl.create_default_context()
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE
                # Constrain to TLS 1.2 or lower so TLS 1.3 ciphersuites do not override set_ciphers
                if hasattr(ssl, "TLSVersion"):
                    ctx.maximum_version = ssl.TLSVersion.TLSv1_2
                try:
                    ctx.set_ciphers(ciphers_str)
                except (ssl.SSLError, ValueError):
                    # OpenSSL build in python does not support these legacy ciphers
                    continue

                with socket.create_connection((host, port), timeout=2.5) as s:
                    with ctx.wrap_socket(s, server_hostname=host) as ssock:
                        negotiated = ssock.cipher()
                        if negotiated and len(negotiated) > 0:
                            cipher_name = negotiated[0].upper()
                            # Verify that the negotiated cipher is genuinely weak and not a fallback
                            is_weak_match = False
                            if profile_key == "NULL" and ("NULL" in cipher_name):
                                is_weak_match = True
                            elif profile_key == "RC4" and ("RC4" in cipher_name):
                                is_weak_match = True
                            elif profile_key == "3DES_SWEET32" and ("3DES" in cipher_name or "DES-CBC3" in cipher_name):
                                is_weak_match = True
                            elif profile_key == "EXPORT" and ("EXP" in cipher_name or "EXPORT" in cipher_name):
                                is_weak_match = True

                            if is_weak_match:
                                evidence = Evidence(
                                    type=EvidenceType.TLS_HANDSHAKE,
                                    summary=f"Completed handshake using weak cipher suite: {negotiated[0]} ({negotiated[1]})",
                                    raw_data={"profile": profile_key, "negotiated_cipher": negotiated}
                                )
                                findings.append(
                                    self.create_finding(
                                        target=target,
                                        title=title,
                                        severity=sev,
                                        confidence=Confidence.CONFIRMED,
                                        status=ObservationStatus.CONFIRMED,
                                        description=f"Server negotiated connection with weak cipher suite '{negotiated[0]}'.",
                                        impact_explanation=explanation,
                                        remediation=f"Disable cipher suites matching '{ciphers_str}' in web server / load balancer configuration.",
                                        verification_command=f"openssl s_client -connect {host}:{port} -cipher '{ciphers_str}'",
                                        evidence=evidence,
                                        category=Category.CRYPTOGRAPHY,
                                        cwe_id=cwe
                                    )
                                )
            except Exception:
                pass
        return findings
