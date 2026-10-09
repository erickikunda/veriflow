"""Explicit, immutable evidence expansion; never an autonomous model tool."""

import hashlib
import json
from pathlib import Path, PurePosixPath

from pydantic import BaseModel, ConfigDict, Field, ValidationError, field_validator, model_validator

from veriflow.bundles import MAX_BUNDLE_BYTES, MAX_SOURCE_BYTES, canonical, get_bundle
from veriflow.domain import VeriFlowError
from veriflow.evidence import read_evidence
from veriflow.indexing import verified_source
from veriflow.persistence import EvidenceBundle, exclusive_worker

MAX_DEPTH = 2
MAX_SNIPPETS = 16


class ExpansionItem(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)
    path: str = Field(min_length=1, max_length=512)
    line: int = Field(ge=1)
    end_line: int = Field(ge=1)
    reason: str = Field(min_length=1, max_length=200)

    @field_validator("path")
    @classmethod
    def safe_path(cls, value):
        path = PurePosixPath(value)
        if path.is_absolute() or ".." in path.parts or "\\" in value:
            raise ValueError("Expected a snapshot-relative path")
        return value

    @model_validator(mode="after")
    def bounded_range(self):
        if not 0 <= self.end_line - self.line < 40 or not self.reason.strip():
            raise ValueError("Expansion requires 1–40 lines and a reason")
        return self


def read_expansion(path):
    try:
        with Path(path).open("rb") as handle:
            raw = handle.read(16 * 1024 + 1)
        if len(raw) > 16 * 1024:
            raise ValueError()
        document = json.loads(raw)
        if not isinstance(document, list) or not 1 <= len(document) <= 4:
            raise ValueError()
        return [ExpansionItem.model_validate(item) for item in document]
    except (ValidationError, ValueError, TypeError):
        raise VeriFlowError(
            "Invalid expansion request; expected 1–4 bounded source ranges"
        ) from None


def expand_bundle(store, parent_id, requests):
    if not 1 <= len(requests) <= 4 or any(not isinstance(item, ExpansionItem) for item in requests):
        raise VeriFlowError("Expansion requires 1–4 validated source ranges")
    store.require_initialized()
    with exclusive_worker(store.root):
        parent = get_bundle(store, parent_id)
        depth = parent.get("expansion_depth", 0)
        if depth >= MAX_DEPTH:
            raise VeriFlowError("Maximum expansion depth reached")
        _, manifest, tree = verified_source(store, parent["run_id"])
        if manifest.snapshot_id != parent["snapshot_id"]:
            raise VeriFlowError("Expansion must use the original snapshot")
        snippets = [dict(item) for item in parent["snippets"]]
        for item in requests:
            if any(
                snippet["path"] == item.path
                and snippet["excerpt_line"] <= item.line
                and snippet["excerpt_end_line"] >= item.end_line
                for snippet in snippets
            ):
                continue
            evidence = read_evidence(manifest, tree, item.path, item.line, item.end_line)
            next_id = max((int(snippet["id"][1:]) for snippet in snippets), default=0) + 1
            snippets.append(
                {
                    "id": f"E{next_id}",
                    "role": "expansion",
                    "reason": item.reason,
                    **{
                        key: evidence[key]
                        for key in ("snapshot_id", "path", "sha256", "line", "end_line", "text")
                    },
                    "excerpt_line": item.line,
                    "excerpt_end_line": item.end_line,
                }
            )
        if len(snippets) == len(parent["snippets"]):
            return parent
        # Expansion honours the envelope the parent was built under, not a second constant.
        bounds = parent.get("envelope") or {}
        source_limit = bounds.get("max_source_bytes", MAX_SOURCE_BYTES)
        snippet_limit = max(MAX_SNIPPETS, bounds.get("max_locations", 0) * 2)
        if (
            len(snippets) > snippet_limit
            or sum(len(item["text"].encode()) for item in snippets) > source_limit
        ):
            raise VeriFlowError("Expanded evidence exceeds the snippet/source budget")
        content = {key: value for key, value in parent.items() if key != "bundle_id"}
        content.update(
            parent_bundle_id=parent_id,
            expansion_version="1",
            expansion_depth=depth + 1,
            expansion_request=[item.model_dump() for item in requests],
            snippets=snippets,
        )
        # Context cannot silently erase extraction/coverage gaps inherited from the parent.
        if len(canonical(content)) > bounds.get("max_bundle_bytes", MAX_BUNDLE_BYTES):
            raise VeriFlowError("Expanded evidence exceeds the configured envelope budget")
        verified_source(store, parent["run_id"])
        identity = hashlib.sha256(canonical(content)).hexdigest()
        with store.transaction() as session:
            source = session.get(EvidenceBundle, parent_id)
            if session.get(EvidenceBundle, identity) is None:
                session.add(
                    EvidenceBundle(id=identity, candidate_id=source.candidate_id, content=content)
                )
        return get_bundle(store, identity)
