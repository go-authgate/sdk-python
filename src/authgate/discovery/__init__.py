"""OIDC auto-discovery from /.well-known/openid-configuration."""

from authgate.discovery.client import DiscoveryClient
from authgate.discovery.models import Metadata

__all__ = ["DiscoveryClient", "Metadata"]
