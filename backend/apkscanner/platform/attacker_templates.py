"""Compatibility facade for runtime attacker templates."""

from ..runtime.attacker_templates import (
    ATTACKER_TEMPLATE_SCHEMA_VERSION,
    attacker_template_catalog,
    materialize_attacker_templates,
)

__all__ = [
    "ATTACKER_TEMPLATE_SCHEMA_VERSION",
    "attacker_template_catalog",
    "materialize_attacker_templates",
]
