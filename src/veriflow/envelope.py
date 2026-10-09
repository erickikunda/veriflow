"""Operator-resolved evidence envelope bounds; limits stay explicit and recorded, never implicit."""

import json
import os
from dataclasses import dataclass, replace
from pathlib import Path

from veriflow.domain import VeriFlowError

FIELDS = {
    "max_locations": (1, 64),
    "max_source_bytes": (1024, 1024 * 1024),
    "max_bundle_bytes": (2048, 2 * 1024 * 1024),
    "max_elided_index": (0, 512),
    "context_lines": (0, 40),
    "max_region_lines": (1, 400),
}
ENVIRONMENT_PREFIX = "VERIFLOW_ENVELOPE_"
CONFIG_VARIABLE = "VERIFLOW_ENVELOPE_CONFIG"


@dataclass(frozen=True)
class Envelope:
    """Bounds applied while materializing one bundle; recorded in the bundle content."""

    max_locations: int = 8
    max_source_bytes: int = 16 * 1024
    max_bundle_bytes: int = 32 * 1024
    max_elided_index: int = 64
    context_lines: int = 3
    max_region_lines: int = 40
    profiles: tuple = ()

    def __post_init__(self):
        for field, (low, high) in FIELDS.items():
            value = getattr(self, field)
            if type(value) is not int or type(value) is bool or not low <= value <= high:
                raise VeriFlowError(f"Envelope {field} must be an integer between {low} and {high}")

    def for_rule(self, rule_id):
        """Per-rule bounds win over the global ones; unknown rules keep the global envelope."""
        for candidate, overrides in self.profiles:
            if candidate == rule_id:
                return replace(self, profiles=(), **overrides)
        return replace(self, profiles=())

    def record(self):
        return {field: getattr(self, field) for field in sorted(FIELDS)}


def _coerce(name, raw):
    try:
        return int(raw)
    except (TypeError, ValueError):
        raise VeriFlowError(f"Envelope {name} must be an integer") from None


def _from_mapping(values, where):
    unknown = set(values) - set(FIELDS)
    if unknown:
        raise VeriFlowError(f"Unsupported envelope field in {where}: {sorted(unknown)[0]}")
    return {name: _coerce(name, value) for name, value in values.items()}


def read_profiles(path):
    """Operator-authored per-rule bounds; repository content never supplies this file."""
    resolved = Path(path)
    if resolved.is_symlink():
        raise VeriFlowError("Envelope configuration cannot be a symlink")
    try:
        with resolved.open("rb") as handle:
            raw = handle.read(64 * 1024 + 1)
    except OSError:
        raise VeriFlowError("Cannot read the envelope configuration file") from None
    if len(raw) > 64 * 1024:
        raise VeriFlowError("Envelope configuration exceeds the 64 KiB limit")
    try:
        document = json.loads(raw)
    except ValueError:
        raise VeriFlowError("Envelope configuration is not valid JSON") from None
    if not isinstance(document, dict) or set(document) - {"defaults", "profiles"}:
        raise VeriFlowError("Envelope configuration accepts only defaults and profiles")
    defaults = document.get("defaults", {})
    profiles = document.get("profiles", {})
    if not isinstance(defaults, dict) or not isinstance(profiles, dict):
        raise VeriFlowError("Envelope defaults and profiles must be objects")
    if len(profiles) > 256:
        raise VeriFlowError("Envelope configuration accepts at most 256 profiles")
    overrides = []
    for rule_id, values in sorted(profiles.items()):
        if not isinstance(rule_id, str) or not 1 <= len(rule_id) <= 200:
            raise VeriFlowError("Envelope profile keys must be rule identifiers")
        if not isinstance(values, dict):
            raise VeriFlowError("Envelope profile entries must be objects")
        overrides.append((rule_id, _from_mapping(values, f"profile {rule_id}")))
    return _from_mapping(defaults, "defaults"), tuple(overrides)


def resolve(config_path=None, overrides=None, environment=None):
    """Precedence: explicit overrides, then environment, then file, then packaged defaults."""
    environment = os.environ if environment is None else environment
    values, profiles = {}, ()
    path = config_path if config_path is not None else environment.get(CONFIG_VARIABLE)
    if path:
        values, profiles = read_profiles(path)
    for field in FIELDS:
        raw = environment.get(ENVIRONMENT_PREFIX + field.upper())
        if raw is not None:
            values[field] = _coerce(field, raw)
    for field, value in (overrides or {}).items():
        if value is not None:
            if field not in FIELDS:
                raise VeriFlowError(f"Unsupported envelope override: {field}")
            values[field] = value
    envelope = Envelope(**values, profiles=profiles)
    if envelope.max_source_bytes >= envelope.max_bundle_bytes:
        raise VeriFlowError("Envelope max_source_bytes must stay below max_bundle_bytes")
    return envelope


def compatibility(envelope, config, rule_id=None):
    """Refuse an envelope the configured provider cannot carry, before any work is done."""
    from veriflow.models import MAX_CITATIONS

    bounds = envelope.for_rule(rule_id)
    if config.provider == "ollama" and bounds.max_bundle_bytes > config.ollama_context_tokens:
        # A full-size bundle could never fit. request_body still applies the exact per-request
        # bound; this only catches an envelope widened without raising the Ollama context.
        raise VeriFlowError(
            f"Envelope max_bundle_bytes {bounds.max_bundle_bytes} exceeds the configured Ollama "
            f"context of {config.ollama_context_tokens}; raise ollama_context_tokens or lower "
            "max_bundle_bytes"
        )
    notes = []
    if bounds.max_locations > MAX_CITATIONS:
        notes.append(
            f"Decisions may cite at most {MAX_CITATIONS} locations, so evidence beyond that "
            "is context the model cannot formally claim"
        )
    return notes
