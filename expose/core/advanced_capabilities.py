"""Advanced Security Capabilities Architecture & Authorization Gates (Phase 28).

Formalizes the architectural boundaries for future enterprise capabilities:
- Authenticated scanning (User explicitly provides authorized access)
- API security (OpenAPI / Swagger import and endpoint contract auditing)
- Repository analysis (GitHub / GitLab source-to-surface correlation)
- Dependency security (Package & SBOM vulnerability analysis)
- Deeper application testing (Explicitly authorized active assessments)
- Cloud / infrastructure security (Separate scope, credentials, and tenant permissions)
- Security posture monitoring (Continuous attack surface monitoring)

Rule 35:
"Do not prematurely implement these."
This module provides strict capability specifications, cryptographic/token authorization
gates, and isolation contracts so that none of these modules can execute prematurely
or without explicit, verified owner consent.
"""

from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field

from expose.core.models import TargetScope


class CapabilityId(str, Enum):
    AUTHENTICATED_SCANNING = "authenticated_scanning"
    API_SECURITY = "api_security"
    REPOSITORY_ANALYSIS = "repository_analysis"
    DEPENDENCY_SECURITY = "dependency_security"
    DEEP_APPLICATION_TESTING = "deep_application_testing"
    CLOUD_INFRASTRUCTURE = "cloud_infrastructure"
    SECURITY_POSTURE_MONITORING = "security_posture_monitoring"


class CapabilityState(str, Enum):
    PLANNED = "planned"
    REQUIRES_EXPLICIT_AUTHORIZATION = "requires_explicit_authorization"
    ACTIVE = "active"


class AuthorizationMethod(str, Enum):
    SIGNED_TOKEN = "signed_token"
    DNS_TXT_VERIFICATION = "dns_txt_verification"
    OAUTH_DELEGATION = "oauth_delegation"
    MUTUAL_TLS = "mutual_tls"


class AuthorizationProof(BaseModel):
    """Cryptographic or verified proof that the scan initiator owns or is authorized to assess the target."""
    proof_id: str
    target_scope: str
    authorized_by: str
    auth_method: AuthorizationMethod
    granted_permissions: List[str] = Field(default_factory=list)
    issued_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    expires_at: datetime
    signature: Optional[str] = None

    def is_valid(self, target_host: str) -> bool:
        now = datetime.now(timezone.utc)
        if now > self.expires_at:
            return False
        # Target must match or be subdomain of authorized scope
        return target_host.endswith(self.target_scope)


class AdvancedCapabilitySpec(BaseModel):
    """Architectural specification for an advanced security capability."""
    id: CapabilityId
    name: str
    description: str
    state: CapabilityState = CapabilityState.PLANNED
    requires_authorization: bool = True
    requires_scope_isolation: bool = True
    required_permissions: List[str] = Field(default_factory=list)
    prerequisites: List[str] = Field(default_factory=list)


class UnauthorizedCapabilityError(PermissionError):
    """Raised when an advanced capability is invoked without verified owner consent or premature activation."""
    pass


class AdvancedCapabilityRegistry:
    """Registry managing advanced capability specifications, gating rules, and authorization boundaries."""

    def __init__(self):
        self._capabilities: Dict[CapabilityId, AdvancedCapabilitySpec] = {}
        self._register_specifications()

    def _register_specifications(self) -> None:
        specs = [
            AdvancedCapabilitySpec(
                id=CapabilityId.AUTHENTICATED_SCANNING,
                name="Authenticated Scanning",
                description="Session-authenticated probing under explicit user authorization.",
                state=CapabilityState.REQUIRES_EXPLICIT_AUTHORIZATION,
                requires_authorization=True,
                requires_scope_isolation=True,
                required_permissions=["scan:authenticated", "session:replay"],
                prerequisites=["target_ownership_verified", "mfa_bypass_agreement"],
            ),
            AdvancedCapabilitySpec(
                id=CapabilityId.API_SECURITY,
                name="API Security & OpenAPI Import",
                description="Contract validation and parameter fuzzing against provided OpenAPI/Swagger specs.",
                state=CapabilityState.REQUIRES_EXPLICIT_AUTHORIZATION,
                requires_authorization=True,
                requires_scope_isolation=True,
                required_permissions=["scan:api_contract"],
                prerequisites=["valid_openapi_spec", "target_scope_confirmed"],
            ),
            AdvancedCapabilitySpec(
                id=CapabilityId.REPOSITORY_ANALYSIS,
                name="Repository Analysis",
                description="Source code and CI/CD secret scanning via GitHub/GitLab integration.",
                state=CapabilityState.REQUIRES_EXPLICIT_AUTHORIZATION,
                requires_authorization=True,
                requires_scope_isolation=True,
                required_permissions=["repo:read"],
                prerequisites=["oauth_installation_token", "read_only_scope"],
            ),
            AdvancedCapabilitySpec(
                id=CapabilityId.DEPENDENCY_SECURITY,
                name="Dependency Security",
                description="Software Bill of Materials (SBOM) and supply-chain dependency scanning.",
                state=CapabilityState.REQUIRES_EXPLICIT_AUTHORIZATION,
                requires_authorization=True,
                requires_scope_isolation=False,
                required_permissions=["package:audit"],
                prerequisites=["manifest_or_lockfile"],
            ),
            AdvancedCapabilitySpec(
                id=CapabilityId.DEEP_APPLICATION_TESTING,
                name="Deeper Application Testing",
                description="Active business logic and intrusive fault-injection assessment.",
                state=CapabilityState.REQUIRES_EXPLICIT_AUTHORIZATION,
                requires_authorization=True,
                requires_scope_isolation=True,
                required_permissions=["scan:intrusive_active", "sla:downtime_waiver"],
                prerequisites=["legal_rules_of_engagement", "emergency_stop_webhook"],
            ),
            AdvancedCapabilitySpec(
                id=CapabilityId.CLOUD_INFRASTRUCTURE,
                name="Cloud / Infrastructure Security",
                description="Multi-cloud posture audits across AWS, GCP, and Azure tenants.",
                state=CapabilityState.REQUIRES_EXPLICIT_AUTHORIZATION,
                requires_authorization=True,
                requires_scope_isolation=True,
                required_permissions=["cloud:audit_read_only"],
                prerequisites=["iam_role_federation", "tenant_isolation_verified"],
            ),
            AdvancedCapabilitySpec(
                id=CapabilityId.SECURITY_POSTURE_MONITORING,
                name="Security Posture Monitoring",
                description="Continuous attack surface monitoring and regression detection.",
                state=CapabilityState.ACTIVE,  # Foundation implemented in Phase 27
                requires_authorization=False,  # Uses public unauthenticated observations
                requires_scope_isolation=False,
                required_permissions=["monitor:public_read"],
                prerequisites=["public_domain_scope"],
            ),
        ]
        for s in specs:
            self._capabilities[s.id] = s

    def get_capability(self, cap_id: CapabilityId) -> Optional[AdvancedCapabilitySpec]:
        return self._capabilities.get(cap_id)

    def list_capabilities(self) -> List[AdvancedCapabilitySpec]:
        return list(self._capabilities.values())

    def assert_can_execute(
        self,
        cap_id: CapabilityId,
        target: TargetScope,
        proof: Optional[AuthorizationProof] = None,
    ) -> None:
        """Enforces Phase 28 authorization gating: blocks execution if permissions or ownership are missing."""
        spec = self._capabilities.get(cap_id)
        if not spec:
            raise ValueError(f"Unknown capability: {cap_id}")

        if spec.state == CapabilityState.PLANNED:
            raise UnauthorizedCapabilityError(
                f"Capability '{spec.name}' is currently in PLANNED state and not active. "
                f"Premature implementation is disallowed per Rule 35."
            )

        if spec.requires_authorization:
            if not proof:
                raise UnauthorizedCapabilityError(
                    f"Explicit user-provided authorization is required to invoke '{spec.name}'. "
                    f"Target '{target.host}' has not provided valid authorization proof."
                )
            if not proof.is_valid(target.host):
                raise UnauthorizedCapabilityError(
                    f"Authorization proof for '{spec.name}' is invalid or expired for target '{target.host}'."
                )
            # Verify all required permissions exist in proof
            for perm in spec.required_permissions:
                if perm not in proof.granted_permissions:
                    raise UnauthorizedCapabilityError(
                        f"Missing required permission '{perm}' in authorization proof for '{spec.name}'."
                    )


_REGISTRY = AdvancedCapabilityRegistry()


def get_advanced_capability_registry() -> AdvancedCapabilityRegistry:
    return _REGISTRY
