"""Attack Surface Asset Models for Expose (Phase 8).

Defines the internal asset hierarchy to answer:
"What does this website expose publicly?"

Target
 ├── Pages
 ├── APIs
 ├── Assets
 ├── Scripts
 └── External dependencies
"""

from typing import Dict, List, Optional
from pydantic import BaseModel, Field


class PageAsset(BaseModel):
    """Discovered page or navigation destination."""
    url: str
    path: str
    title: Optional[str] = None
    status_code: Optional[int] = None
    is_internal: bool = True
    discovered_via: str = "html_anchor"  # html_anchor, sitemap, robots_txt


class APIAsset(BaseModel):
    """Discovered or referenced backend API endpoint."""
    path: str
    method: str = "ANY"
    source_script: Optional[str] = None
    parameters: List[str] = Field(default_factory=list)
    is_public: bool = True


class StaticAsset(BaseModel):
    """Discovered static resource (stylesheet, image, font, media, manifest)."""
    url: str
    asset_type: str  # stylesheet, image, font, media, manifest, icon
    mime_type: Optional[str] = None
    is_external: bool = False


class ScriptAsset(BaseModel):
    """Discovered JavaScript resource."""
    url: str
    is_external: bool = False
    cdn_provider: Optional[str] = None
    has_sri: bool = False
    sri_hash: Optional[str] = None


class FormInput(BaseModel):
    """Input field inside a web form."""
    name: str
    input_type: str = "text"
    is_sensitive: bool = False


class FormAsset(BaseModel):
    """Discovered HTML submission form."""
    action: str
    method: str = "GET"
    inputs: List[FormInput] = Field(default_factory=list)
    has_password: bool = False
    is_secure_action: bool = True


class ExternalDependency(BaseModel):
    """Third-party domain or external service provider referenced by the application."""
    origin: str
    category: str = "CDN"  # CDN, Analytics, Fonts, Social, Ads, Auth, Unknown
    resource_count: int = 1
    sample_urls: List[str] = Field(default_factory=list)


class RobotsTxtAsset(BaseModel):
    """Parsed robots.txt rules and directives."""
    is_present: bool = False
    disallowed_paths: List[str] = Field(default_factory=list)
    allowed_paths: List[str] = Field(default_factory=list)
    sitemaps: List[str] = Field(default_factory=list)


class AttackSurface(BaseModel):
    """Complete attack surface asset model answering: What does this website expose publicly?"""
    target: str
    pages: List[PageAsset] = Field(default_factory=list)
    apis: List[APIAsset] = Field(default_factory=list)
    assets: List[StaticAsset] = Field(default_factory=list)
    scripts: List[ScriptAsset] = Field(default_factory=list)
    forms: List[FormAsset] = Field(default_factory=list)
    external_dependencies: List[ExternalDependency] = Field(default_factory=list)
    robots_txt: Optional[RobotsTxtAsset] = None
    sitemaps: List[str] = Field(default_factory=list)
    exposure_summary: str = ""
