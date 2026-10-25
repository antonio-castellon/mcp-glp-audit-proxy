"""Transport-agnostic core.

These names do not open a client socket and do not speak HTTP. Channel
adapters call them. Importing a name from here is the same object as
importing it from its historical module.
"""

from __future__ import annotations

from ..anchor import assess, verify_anchored
from ..approvals import load_approvals
from ..canonical import SCHEMA_VERSION, canonicalize, seal
from ..chain import verify_bytes, verify_file
from ..checkpoints import check_log
from ..features import FeatureSet
from ..interfaces import AuditStore, IdentityProvider, Reporter, Signer
from ..policy import Policy
from ..wiring import build_components

__all__ = [
    "AuditStore",
    "FeatureSet",
    "IdentityProvider",
    "Policy",
    "Reporter",
    "SCHEMA_VERSION",
    "Signer",
    "assess",
    "build_components",
    "canonicalize",
    "check_log",
    "load_approvals",
    "seal",
    "verify_anchored",
    "verify_bytes",
    "verify_file",
]
