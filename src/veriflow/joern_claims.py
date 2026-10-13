"""Explicit bounded Joern review gates; no exploitability or safety claims."""

import hashlib
import json
from importlib.resources import files
from pathlib import Path

from veriflow.domain import VeriFlowError

POLICY = "joern-spring-review-v1"
RULE = "veriflow/joern-spring-get-jdbc-sql-v1"


RUST_POLICY = "joern-rust-env-review-v1"

GO_POLICY = "joern-go-http-review-v1"

CSHARP_POLICY = "joern-csharp-review-v1"

FLASK_POLICY = "joern-flask-review-v1"
FLASK_RULE = "veriflow/joern-python-flask-system-v1"
PROFILES = {
    RUST_POLICY: (
        "rust",
        "rust-env-shell-v1",
        "veriflow/joern-rust-env-shell-v1",
        "joern-rust-env-shell.sc",
    ),
    GO_POLICY: (
        "go",
        "go-http-shell-v1",
        "veriflow/joern-go-http-shell-v1",
        "joern-go-http-shell.sc",
    ),
    CSHARP_POLICY: (
        "csharp",
        "default",
        "veriflow/joern-csharp-lookup-commandtext-v1",
        "joern-csharp-flow.sc",
    ),
    POLICY: ("java", "default", RULE, "joern-java-flow.sc"),
    FLASK_POLICY: ("python", "python-flask-system-v1", FLASK_RULE, "joern-python-flask-system.sc"),
}

for _language in ("javascript", "typescript"):
    PROFILES[f"joern-{_language}-express-review-v1"] = (
        _language,
        "express-request-eval-v1",
        f"veriflow/joern-{_language}-express-eval-v1",
        f"joern-{_language}-express-eval.sc",
    )
for _language in ("c", "cpp"):
    PROFILES[f"joern-{_language}-argv-review-v1"] = (
        _language,
        "c-family-argv-system-v1",
        f"veriflow/joern-{_language}-argv-system-v1",
        f"joern-{_language}-argv-system.sc",
    )
C_FAMILY_POLICIES = {"joern-c-argv-review-v1", "joern-cpp-argv-review-v1"}
RULE_POLICIES = {profile[2]: policy for policy, profile in PROFILES.items()}

# Default gate for runtime profiles: native/SARIF/source consistency and claims bound to the
# recorded path endpoints. Endpoint syntax is not checked; no profile-specific code exists.
RUNTIME_GATE = "runtime-native-v1"


def is_runtime(policy):
    return isinstance(policy, str) and policy.startswith(f"{RUNTIME_GATE}:")


def runtime_policies(store):
    """policy -> (language, profile, rule, query_sha256) from this store's active catalog."""
    if store is None:
        return {}
    from veriflow.joern_profiles import catalog

    return {
        f"{RUNTIME_GATE}:{b.name}": (b.language, b.name, b.rule_id, b.query_sha256)
        for b in catalog(store).bindings
        if b.review_gate == RUNTIME_GATE
    }


def require_policy(policy, store=None):
    if policy in PROFILES:
        return PROFILES[policy]
    runtime = runtime_policies(store) if is_runtime(policy) else {}
    if policy in runtime:
        return runtime[policy]
    raise VeriFlowError("Unsupported explicit review policy")


def policy_for(language, discovery_profile, store=None):
    """Reviewed policy for one discovery profile, or None when no reviewed gate exists."""
    matches = [
        policy
        for policy, spec in {**PROFILES, **runtime_policies(store)}.items()
        if spec[:2] == (language, discovery_profile or "default")
    ]
    return matches[0] if len(matches) == 1 else None


def policy_for_rule(rule, store=None):
    """Gate policy for a candidate rule; packaged reviewed gates first, then runtime gates."""
    if rule in RULE_POLICIES:
        return RULE_POLICIES[rule]
    return next(
        (policy for policy, spec in runtime_policies(store).items() if spec[2] == rule), None
    )


def query_digest(policy=POLICY, store=None):
    if is_runtime(policy):
        return require_policy(policy, store)[3]
    return hashlib.sha256(
        files("veriflow").joinpath("queries/" + require_policy(policy)[3]).read_bytes()
    ).hexdigest()


def runtime_anchors(bundle, snippet, claim):
    """A source/sink claim must cite the recorded endpoint node line and quote its code."""
    from veriflow.source_context import covers_flow_step

    if claim.obligation not in {"source", "sink"}:
        return []  # Guard presence/safety is deliberately unsupported; use unknown.
    nodes = bundle.get("joern_native_audit", {}).get("nodes", [])
    if not nodes:
        return []
    node = nodes[0 if claim.obligation == "source" else -1]
    if (
        snippet.get("path") != node.get("path")
        or snippet.get("sha256") != node.get("sha256")
        or not covers_flow_step(snippet, node.get("flow_step"))
        or claim.line != node.get("line")
        or claim.end_line != claim.line
        or not node.get("code")
        or node["code"] not in claim.quote
    ):
        return []
    # Quote the whole endpoint line, so a short node code cannot be cited as a fragment.
    lines = snippet.get("text", "").splitlines()
    offset = claim.line - snippet.get("excerpt_line", 0)
    if not 0 <= offset < len(lines) or claim.quote.strip() != lines[offset].strip():
        return []
    return [(claim.line, claim.line)]


def native_audit(
    root, report, manifest, tree, sarif, result, *, policy=POLICY, max_nodes=None, store=None
):
    """Bind one selected SARIF path to pinned native output and source coordinates."""
    from veriflow.joern import MAX_SARIF_BYTES, VERSION, decode_output, to_sarif
    from veriflow.joern_profiles import message_for

    language, profile, rule, _ = require_policy(policy, store)
    audit = {"policy_id": policy, "status": "unavailable", "reason": "missing_native_provenance"}
    if not report.get("native_output_sha256"):
        return audit
    try:
        scanner = report.get("scanner", {})
        if (
            scanner.get("engine_id") != "joern"
            or scanner.get("version") != VERSION
            or report.get("language") != language
            or report.get("discovery_profile", "default") != profile
            or report.get("query_sha256") != query_digest(policy, store)
        ):
            raise VeriFlowError("unsupported_native_profile")
        native_path = root / "flows.json"
        if native_path.is_symlink():
            raise VeriFlowError("native_artifact_symlink")
        with native_path.open("rb") as handle:
            raw = handle.read(MAX_SARIF_BYTES + 1)
        if (
            len(raw) > MAX_SARIF_BYTES
            or hashlib.sha256(raw).hexdigest() != report["native_output_sha256"]
        ):
            raise VeriFlowError("native_integrity")
        doc = decode_output(raw, language, rule)
        extra = {}
        if policy == CSHARP_POLICY:
            from veriflow.csharp_locations import VERSION as span_version
            from veriflow.joern_csharp import map_output

            identity = report.get("repair_identity", {})
            if not valid_repair_identity(identity):
                raise VeriFlowError("unsupported_repair_identity")
            paths = doc["paths"]
            if (
                len(paths) > 32
                or any(not isinstance(path, list) for path in paths)
                or sum(len(path) for path in paths) > 128
            ):
                raise VeriFlowError("native_mapping_limit")
            raw, mapping = map_output(
                doc, root / "source", [f for f in manifest.files if f.path.endswith(".cs")]
            )
            recorded = report.get("source_mapping", {})
            if any(recorded.get(k) != mapping[k] for k in ("validated_paths", "unsupported_paths")):
                raise VeriFlowError("source_mapping_mismatch")
            doc = decode_output(raw, language, rule)
            extra = {"repair_identity": identity, "span_version": span_version}
        regenerated = to_sarif(
            raw, root / "source", manifest, language, rule, message_for(rule, language, store)
        )
        if regenerated != sarif:
            raise VeriFlowError("native_sarif_mismatch")
        matches = [
            i
            for i, item in enumerate(json.loads(regenerated)["runs"][0]["results"])
            if item == result
        ]
        if len(matches) != 1:
            raise VeriFlowError("ambiguous_native_path")
        path = doc["paths"][matches[0]]
        # The audit tracks the same envelope the bundle is built under; a second constant here
        # would cap the path before the widened envelope could ever be applied.
        ceiling = max_nodes if max_nodes is not None else (8 if policy == RUST_POLICY else 7)
        if not 2 <= len(path) <= ceiling:
            raise VeriFlowError("native_path_limit")
        records = {f.path: f for f in manifest.files}
        nodes = []
        for step, node in enumerate(path):
            location = Path(node["file"])
            if location.is_absolute():
                location = location.relative_to(root / "source")
            relative = location.as_posix()
            record = records[relative]
            if record.size_bytes > 1024 * 1024:
                raise VeriFlowError("native_source_file_limit")
            contents = (tree / relative).read_bytes()
            if hashlib.sha256(contents).hexdigest() != record.sha256:
                raise VeriFlowError("source_integrity")
            code = node["code"]
            line = node["line"]
            if not isinstance(code, str) or not code.strip() or len(code) > 2000:
                raise VeriFlowError("unsupported_native_code")
            on_source = code in contents.decode("utf-8").splitlines()[line - 1]
            endpoint = step in (0, len(path) - 1)
            if not on_source and (policy != FLASK_POLICY or endpoint):
                raise VeriFlowError("native_code_not_on_source_line")
            nodes.append(
                {
                    "flow_step": step,
                    "path": relative,
                    "line": line,
                    "sha256": record.sha256,
                    "code": code,
                    **({"source_literal": on_source} if policy == FLASK_POLICY else {}),
                }
            )
        return {
            **extra,
            "policy_id": policy,
            "status": "validated",
            "scanner_version": VERSION,
            "query_sha256": report["query_sha256"],
            "native_output_sha256": report["native_output_sha256"],
            "sarif_sha256": report["sarif_sha256"],
            "nodes": nodes,
            "scope": "native/SARIF/source coordinate consistency, not semantic proof",
        }
    except (
        VeriFlowError,
        OSError,
        ValueError,
        KeyError,
        IndexError,
        TypeError,
        UnicodeError,
    ) as exc:
        return {
            **audit,
            "status": "withheld",
            "reason": str(exc) if isinstance(exc, VeriFlowError) else "invalid_native_evidence",
        }


def review_preflight(bundle, policy=POLICY, store=None):
    """Native/context/syntax eligibility only; produces no advisory decision."""
    from types import SimpleNamespace

    from veriflow.claims import bundle_engine
    from veriflow.joern import VERSION
    from veriflow.source_context import complete_context

    language, _, rule, _ = require_policy(policy, store)
    report = {
        "policy_id": policy,
        "engine_id": bundle_engine(bundle),
        "status": "insufficient_native_evidence",
        "passed": False,
        "reachability_proven": False,
        "automatic_triage_enabled": False,
        "scope": "bounded advisory evidence consistency; not exploitability or safety",
    }
    if bundle_engine(bundle) != "joern" or bundle.get("rule_id") != rule:
        return {**report, "status": "unsupported_profile"}
    if bundle.get("status") != "ready":
        return {**report, "status": "incomplete_bundle"}
    audit = bundle.get("joern_native_audit", {})
    if (
        audit.get("status") != "validated"
        or audit.get("policy_id") != policy
        or audit.get("scanner_version") != VERSION
        or audit.get("query_sha256") != query_digest(policy, store)
        or audit.get("sarif_sha256") != bundle.get("sarif_sha256")
        or not isinstance(audit.get("native_output_sha256"), str)
        or len(audit["native_output_sha256"]) != 64
    ):
        return report
    if policy == CSHARP_POLICY:
        from veriflow.csharp_locations import VERSION as span_version

        if (
            not valid_repair_identity(audit.get("repair_identity", {}))
            or audit.get("span_version") != span_version
        ):
            return report
    nodes = audit.get("nodes", [])
    retained = [s for s in bundle["snippets"] if s.get("flow_id") is not None]
    # Track the envelope the bundle was actually built with instead of a second magic bound.
    recorded = bundle.get("location_limit")
    ceiling = (recorded - 1) if isinstance(recorded, int) else (8 if policy == RUST_POLICY else 7)
    # A snippet may stand for several flow steps that bind to one region; every step still maps.
    covered = {}
    for snippet in retained:
        for step in snippet.get("flow_steps_covered") or [snippet.get("flow_step")]:
            if step in covered:
                return report
            covered[step] = snippet
    if not 2 <= len(nodes) <= ceiling or sorted(covered) != list(range(len(nodes))):
        return report
    runtime = is_runtime(policy)
    for step, node in enumerate(nodes):
        snippet = covered[step]
        if (
            node.get("flow_step") != step
            or snippet.get("flow_id") != "F0T0"
            or snippet.get("flow_steps") != len(nodes)
            or snippet.get("path") != node.get("path")
            or snippet.get("sha256") != node.get("sha256")
            or snippet.get("line") != node.get("line")
            or snippet.get("end_line") != node.get("line")
        ):
            return report
        context = complete_context(
            bundle,
            snippet,
            {
                "java": ".java",
                "python": ".py",
                "javascript": ".js",
                "typescript": ".ts",
                "csharp": ".cs",
                "go": ".go",
                "rust": ".rs",
                "c": (".c", ".h"),
                "cpp": (".cpp", ".h", ".hpp"),
            }[language],
        )
        if context is None:
            # Name the reconstruction failure; a generic status sends operators hunting.
            return {**report, "status": "incomplete_source_context"}
        if hashlib.sha256(context.encode()).hexdigest() != node["sha256"]:
            return report
        lines = snippet["text"].splitlines()
        offset = node["line"] - snippet["excerpt_line"]
        if (
            not 0 <= offset < len(lines)
            or not node.get("code")
            or (
                (policy != FLASK_POLICY or step in (0, len(nodes) - 1))
                and node["code"] not in lines[offset]
            )
            or (
                policy == FLASK_POLICY
                and node.get("source_literal") != (node["code"] in lines[offset])
            )
        ):
            return report
    if runtime:
        # Native path and source coordinates agree; no syntax vocabulary exists for this query.
        return {
            **report,
            "status": "eligible_for_advisory",
            "passed": True,
            "gate": RUNTIME_GATE,
            "endpoint_syntax_verified": False,
            "assurance": "path_citation_only",
        }
    # Endpoints bind to real node steps, so a snippet standing for several steps still anchors.
    endpoints = [("source", 0), ("sink", len(nodes) - 1)]
    for obligation, endpoint_step in endpoints:
        snippet = {**covered[endpoint_step], "flow_step": endpoint_step}
        line = snippet["line"]
        quote = snippet["text"].splitlines()[line - snippet["excerpt_line"]].strip()
        anchor = SimpleNamespace(obligation=obligation, line=line, end_line=line, quote=quote)
        if policy == POLICY:
            from veriflow.java_claims import anchors
        elif policy in C_FAMILY_POLICIES:
            from veriflow.joern_c_family_claims import anchors
        elif policy == RUST_POLICY:
            from veriflow.joern_rust_claims import anchors
        elif policy == GO_POLICY:
            from veriflow.joern_go_claims import anchors
        elif policy == CSHARP_POLICY:
            from veriflow.joern_csharp_claims import anchors
        elif policy == FLASK_POLICY:
            from veriflow.joern_flask_claims import anchors
        else:
            from veriflow.joern_express_claims import anchors
        if not anchors(bundle, snippet, anchor):
            return {**report, "status": "unsupported_endpoint_syntax"}
    return {**report, "status": "eligible_for_advisory", "passed": True}


def spring_preflight(bundle):
    return review_preflight(bundle, POLICY)


def policy_requirements(policy=POLICY, store=None):
    language, profile, _, _ = require_policy(policy, store)
    if is_runtime(policy):
        return {
            "policy_id": policy,
            "query_sha256": query_digest(policy, store),
            "engine_id": "joern",
            "supported": True,
            "required": ["source", "sink", "flow", "guard"],
            "negative_requires": "Negative suggestions unsupported; abstain instead",
            "modeled_source": (
                f"Runtime profile {profile}: quote the complete source lines of the recorded "
                "first and last path nodes; their syntax is not independently verified"
            ),
            "endpoint_syntax_verified": False,
            "scope": "Native path consistency only; no syntax, exploitability or safety proof",
        }
    return {
        "policy_id": policy,
        "query_sha256": query_digest(policy),
        "engine_id": "joern",
        "supported": True,
        "required": ["source", "sink", "flow", "guard"],
        "negative_requires": "Negative suggestions unsupported; abstain instead",
        "modeled_source": (
            "Explicit Spring RequestParam syntax and complete native-bound context"
            if policy == POLICY
            else "Global main argv literal index to direct system; libc identity unproven"
            if policy in C_FAMILY_POLICIES
            else "std::env::var literal key to Command shell -c chain; complete context"
            if policy == RUST_POLICY
            else "Bound net/http Request form input to os/exec.Command shell -c; complete context"
            if policy == GO_POLICY
            else "FromQuery/classic HttpGet to CommandText RHS syntax; complete context"
            if policy == CSHARP_POLICY
            else "Bound Flask args/form.get literal key to os.system; complete native-bound context"
            if policy == FLASK_POLICY
            else "Explicit Express get/post inline request field to direct eval; complete context"
        ),
        **(
            {
                "intermediate_nodes": (
                    "Native tool observations; generated code is not source or semantic proof"
                )
            }
            if policy == FLASK_POLICY
            else {}
        ),
        "scope": "Advisory quote/syntax/path consistency; no exploitability or safety proof",
    }


def assess_review_evidence(bundle, decision, policy=POLICY, store=None):
    """Explicit policy only; the default shared triage registry stays unsupported."""
    from veriflow.claims import POLICIES, _assess_supported

    preflight = review_preflight(bundle, policy, store)
    if decision.verdict == "abstain":
        return {**preflight, "status": "abstained", "passed": False}
    if decision.verdict != "needs_review":
        return {**preflight, "status": "unsupported_negative_verdict", "passed": False}
    if not preflight["passed"]:
        return preflight
    checked = _assess_supported(
        bundle,
        decision,
        {"language": "joern_runtime", "sinks": []}
        if is_runtime(policy)
        else POLICIES["java/sql-injection"]
        if policy == POLICY
        else {
            "language": "joern_c_family"
            if policy in C_FAMILY_POLICIES
            else "joern_rust"
            if policy == RUST_POLICY
            else "joern_go"
            if policy == GO_POLICY
            else "joern_csharp"
            if policy == CSHARP_POLICY
            else "joern_flask"
            if policy == FLASK_POLICY
            else "joern_express",
            "sinks": [],
        },
    )
    return {**checked, **{k: v for k, v in preflight.items() if k not in {"status", "passed"}}}


def assess_spring_evidence(bundle, decision):
    return assess_review_evidence(bundle, decision, POLICY)


def valid_repair_identity(identity):
    from veriflow.joern_csharp import PATCHED_SHA256

    if not isinstance(identity, dict):
        return False
    receipt = identity.get("receipt_sha256")
    return (
        identity.get("patched_source_sha256") == PATCHED_SHA256
        and isinstance(receipt, str)
        and len(receipt) == 64
        and all(c in "0123456789abcdef" for c in receipt)
    )
