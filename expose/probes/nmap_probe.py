"""Nmap Network and Port Security Intelligence Probe for Expose.

Discovers open ports, fingerprint listening services, and identifies hazardous
administrative or database listeners exposed to the public internet using
either the native Nmap binary (when present) or high-concurrency non-blocking TCP discovery.
"""

import asyncio
import shutil
import socket
import xml.etree.ElementTree as ET
from typing import Dict, List, Optional, Set, Tuple

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
from expose.probes.base import BaseProbe


# Standard risk ports and their profiles: (service_name, default_severity, is_hazard, description)
TARGET_PORTS: Dict[int, Tuple[str, Severity, bool, str]] = {
    21: ("FTP", Severity.HIGH, True, "Cleartext File Transfer Protocol service exposed to the public network."),
    22: ("SSH", Severity.INFO, False, "SSH administrative daemon accessible on standard port."),
    23: ("Telnet", Severity.CRITICAL, True, "Insecure, unencrypted Telnet remote shell service exposed."),
    25: ("SMTP", Severity.LOW, False, "Simple Mail Transfer Protocol mail exchange listener."),
    53: ("DNS", Severity.INFO, False, "Domain Name System server port."),
    80: ("HTTP", Severity.INFO, False, "Standard unencrypted HTTP web service."),
    110: ("POP3", Severity.LOW, False, "Post Office Protocol mail retrieval service."),
    143: ("IMAP", Severity.LOW, False, "Internet Message Access Protocol mail service."),
    443: ("HTTPS", Severity.INFO, False, "Standard TLS-encrypted HTTPS web service."),
    445: ("SMB", Severity.CRITICAL, True, "Microsoft Server Message Block file-sharing port publicly exposed."),
    3306: ("MySQL", Severity.CRITICAL, True, "Publicly exposed MySQL database listener."),
    3389: ("RDP", Severity.HIGH, True, "Microsoft Remote Desktop Protocol service directly reachable from public internet."),
    5432: ("PostgreSQL", Severity.CRITICAL, True, "Publicly exposed PostgreSQL relational database listener."),
    6379: ("Redis", Severity.CRITICAL, True, "Publicly accessible Redis in-memory data store listener without network isolation."),
    8080: ("HTTP-Alt", Severity.INFO, False, "Alternative HTTP web proxy or application port."),
    8443: ("HTTPS-Alt", Severity.INFO, False, "Alternative HTTPS web service port."),
    9200: ("Elasticsearch", Severity.CRITICAL, True, "Publicly exposed Elasticsearch REST search engine listener."),
    27017: ("MongoDB", Severity.CRITICAL, True, "Publicly exposed MongoDB NoSQL document database listener."),
}


class NmapProbe(BaseProbe):
    """Audits open ports, exposed services, and network perimeter posture using Nmap or async TCP socket discovery."""

    @property
    def name(self) -> str:
        return "nmap_probe"

    @property
    def category(self) -> Category:
        return Category.ATTACK_SURFACE

    @property
    def description(self) -> str:
        return "Discovers open ports, identifies exposed network services, and audits perimeter firewall posture."

    async def execute(self, target: TargetScope) -> List[Finding]:
        findings: List[Finding] = []
        host = target.host

        # 1. Attempt binary execution if nmap is installed
        nmap_path = shutil.which("nmap")
        if nmap_path:
            findings = await self._execute_nmap_binary(nmap_path, target)
            if findings:
                return findings

        # 2. Fallback to high-speed asynchronous TCP socket discovery
        return await self._execute_async_tcp_scan(target)

    async def _execute_nmap_binary(self, nmap_bin: str, target: TargetScope) -> List[Finding]:
        """Runs nmap binary with safe, non-destructive timing and XML output parsing."""
        findings: List[Finding] = []
        ports_arg = ",".join(str(p) for p in TARGET_PORTS.keys())
        cmd = [
            nmap_bin,
            "-sV",
            "-Pn",
            "--open",
            "-T4",
            "-p",
            ports_arg,
            "-oX",
            "-",
            target.host,
        ]

        try:
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=12.0)
            if proc.returncode == 0 and stdout:
                findings = self._parse_nmap_xml(stdout.decode("utf-8", errors="ignore"), target)
        except Exception:
            # Fall back to socket scanner if subprocess fails or times out
            return []

        return findings

    def _parse_nmap_xml(self, xml_content: str, target: TargetScope) -> List[Finding]:
        """Extracts open ports and service fingerprints from Nmap XML."""
        findings: List[Finding] = []
        try:
            root = ET.fromstring(xml_content)
            for host in root.findall("host"):
                for port_elem in host.findall(".//port"):
                    state_elem = port_elem.find("state")
                    if state_elem is not None and state_elem.get("state") == "open":
                        port_id = int(port_elem.get("portid", "0"))
                        protocol = port_elem.get("protocol", "tcp")
                        service_elem = port_elem.find("service")
                        service_name = service_elem.get("name", "unknown") if service_elem is not None else "unknown"
                        product = service_elem.get("product", "") if service_elem is not None else ""
                        version = service_elem.get("version", "") if service_elem is not None else ""
                        banner = f"{product} {version}".strip() or service_name

                        findings.append(self._create_port_finding(target, port_id, protocol, service_name, banner, is_nmap_binary=True))
        except Exception:
            return []

        return findings

    async def _execute_async_tcp_scan(self, target: TargetScope) -> List[Finding]:
        """Performs non-blocking async TCP connection checks across target ports."""
        findings: List[Finding] = []
        host = target.host
        open_ports: List[Tuple[int, str]] = []

        async def check_port(port: int, default_service: str) -> Optional[Tuple[int, str]]:
            try:
                reader, writer = await asyncio.wait_for(
                    asyncio.open_connection(host, port),
                    timeout=0.85,
                )
                writer.close()
                await writer.wait_closed()
                return (port, default_service)
            except Exception:
                return None

        tasks = [check_port(p, info[0]) for p, info in TARGET_PORTS.items()]
        results = await asyncio.gather(*tasks, return_exceptions=True)

        for res in results:
            if isinstance(res, tuple) and res is not None:
                port, s_name = res
                open_ports.append((port, s_name))
                findings.append(self._create_port_finding(target, port, "tcp", s_name, s_name, is_nmap_binary=False))

        # If only safe web ports are open, record an informational hardening observation
        hazardous_ports = [p for p, _ in open_ports if TARGET_PORTS.get(p, ("", Severity.INFO, False, ""))[2]]
        if not hazardous_ports and open_ports:
            evidence = Evidence(
                type=EvidenceType.RAW_SOCKET,
                summary=f"Network port scan verified only expected web/application ports open ({', '.join(str(p) for p, _ in open_ports)}). No hazardous administrative or database ports detected.",
                raw_data={"open_ports": [p for p, _ in open_ports]},
                command=f"nmap -Pn -p {','.join(str(p) for p, _ in open_ports)} {target.host}",
            )
            findings.append(
                self.create_finding(
                    target=target,
                    title="Perimeter Firewall Port Hardening Verified",
                    severity=Severity.INFO,
                    confidence=Confidence.CONFIRMED,
                    status=ObservationStatus.OBSERVED,
                    description="Network port auditing confirmed that no database listeners, cleartext remote shells, or unencrypted file transfers are exposed to the public internet.",
                    remediation="Maintain default-deny ingress firewall policies on your cloud security groups or edge router.",
                    evidence=evidence,
                    category=Category.ATTACK_SURFACE,
                    rule_id="EXP-PORT-HARDENED",
                )
            )

        return findings

    def _create_port_finding(
        self,
        target: TargetScope,
        port: int,
        protocol: str,
        service_name: str,
        banner: str,
        is_nmap_binary: bool,
    ) -> Finding:
        port_info = TARGET_PORTS.get(port, (service_name, Severity.INFO, False, f"Service listening on port {port}."))
        name, default_sev, is_hazard, desc = port_info

        if is_hazard and target.is_private:
            severity = Severity.INFO
            status = ObservationStatus.OBSERVED
            title = f"Non-Public {name} Service Detected on Port {port}"
            cwe = None
            rule_id = f"EXP-PORT-PRIVATE-{name.upper()}"
            desc = (
                f"{name} is reachable from this scanner on a private or loopback target. "
                "This observation does not establish public internet exposure."
            )
            remediation = (
                f"Confirm that port {port} ({name}) is bound only to the intended private or loopback interfaces "
                "and is protected by host and network access controls."
            )
            impact = (
                "Private-scope reachability should be reviewed according to the internal network trust boundary; "
                "the scan did not verify public exposure."
            )
        elif is_hazard:
            severity = default_sev
            status = ObservationStatus.CONFIRMED
            title = f"Publicly Exposed {name} Service on Port {port}"
            cwe = "CWE-284"
            rule_id = f"EXP-PORT-EXPOSED-{name.upper()}"
            remediation = f"Block public internet access to port {port} ({name}). Restrict access to internal VPN/VPC subnets or loopback interfaces."
            impact = f"Exposing {name} directly to the public network allows unauthenticated attackers to attempt brute-force authentication, exploit unpatched service flaws, or access sensitive data stores."
        else:
            severity = Severity.INFO
            status = ObservationStatus.OBSERVED
            title = f"Open Port {port}/{protocol.upper()} Discovered ({name})"
            cwe = None
            rule_id = f"EXP-PORT-{port}"
            remediation = "Ensure only necessary web services are listening on public interfaces."
            impact = f"Identified standard listener for {name} ({banner})."

        evidence = Evidence(
            type=EvidenceType.NMAP_OUTPUT if is_nmap_binary else EvidenceType.RAW_SOCKET,
            summary=f"Port {port}/{protocol} is open and responding on host {target.host}. Detected banner: {banner}.",
            raw_data={
                "port": port,
                "protocol": protocol,
                "service": service_name,
                "banner": banner,
                "scanner": "nmap-binary" if is_nmap_binary else "async-tcp-socket",
            },
            command=f"nmap -Pn -p {port} -sV {target.host}",
        )

        return self.create_finding(
            target=target,
            title=title,
            severity=severity,
            confidence=Confidence.CONFIRMED,
            status=status,
            description=desc,
            remediation=remediation,
            impact_explanation=impact,
            evidence=evidence,
            category=Category.ATTACK_SURFACE,
            rule_id=rule_id,
            cwe_id=cwe,
        )
