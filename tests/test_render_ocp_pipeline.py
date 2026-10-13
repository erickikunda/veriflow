import importlib.util
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location(
    "render_ocp_pipeline", ROOT / "scripts/render_ocp_pipeline.py"
)
renderer = importlib.util.module_from_spec(spec)
spec.loader.exec_module(renderer)

IMAGE = "registry.example/veriflow-pipeline@sha256:" + "a" * 64
OLLAMA = "registry.example/ollama@sha256:" + "b" * 64


def render(provider, **kwargs):
    return renderer.bundle(
        "scan", "nightly", IMAGE, "input", "reports", "state", "advisory", provider, **kwargs
    )


def items(data):
    return {item["kind"]: item for item in data["items"]}


def test_hosted_provider_job_has_secret_env_and_bounded_egress():
    data = items(
        render(
            "anthropic",
            api_key_secret="anthropic-key",
            api_key_env="TRACEPROOF_ANTHROPIC_API_KEY",
            egress_cidrs=["203.0.113.0/24"],
            toolchain="csharp",
            llm_discovery=True,
        )
    )
    pod = data["Job"]["spec"]["template"]["spec"]
    container = pod["containers"][0]
    assert container["args"][:3] == ["--state-dir", "/state", "run-pipeline-from-csv"]
    assert "/reports/nightly" in container["args"] and "--llm-discovery" in container["args"]
    assert container["args"][-3:-1] == ["--joern-repair-dir", "/opt/veriflow/csharp-repair"]
    assert container["env"][0] == {"name": "VERIFLOW_PROFILE_MODE", "value": "trusted-directory"}
    assert container["env"][1]["valueFrom"]["secretKeyRef"]["name"] == "anthropic-key"
    assert "initContainers" not in pod
    egress = data["NetworkPolicy"]["spec"]["egress"]
    assert egress[1] == {
        "to": [{"ipBlock": {"cidr": "203.0.113.0/24"}}],
        "ports": [{"protocol": "TCP", "port": 443}],
    }
    assert data["Job"]["spec"]["backoffLimit"] == 0


def test_ollama_runs_as_loopback_sidecar_without_egress():
    data = items(render("ollama", ollama_image=OLLAMA, ollama_models_pvc="models"))
    pod = data["Job"]["spec"]["template"]["spec"]
    sidecar = pod["initContainers"][0]
    assert sidecar["restartPolicy"] == "Always" and sidecar["image"] == OLLAMA
    assert sidecar["startupProbe"]["exec"]["command"] == ["ollama", "list"]
    mounts = {m["mountPath"] for m in pod["containers"][0]["volumeMounts"]}
    assert {"/work", "/tmp", "/state"} <= mounts
    assert {"name": "OLLAMA_HOST", "value": "127.0.0.1:11434"} in sidecar["env"]
    assert data["NetworkPolicy"]["spec"]["egress"] == []
    assert pod["containers"][0]["env"] == [
        {"name": "VERIFLOW_PROFILE_MODE", "value": "trusted-directory"}
    ]
    approved = items(
        render("ollama", ollama_image=OLLAMA, ollama_models_pvc="models", profile_mode="approved")
    )
    env = approved["Job"]["spec"]["template"]["spec"]["containers"][0]["env"]
    assert env == [{"name": "VERIFLOW_PROFILE_MODE", "value": "approved"}]


@pytest.mark.parametrize(
    "provider,kwargs,message",
    [
        ("openai", {"api_key_secret": "k", "api_key_env": "KEY"}, "egress-cidr"),
        ("openai", {"egress_cidrs": ["10.0.0.0/8"]}, "api-key-secret"),
        ("ollama", {"ollama_image": "ollama:latest", "ollama_models_pvc": "m"}, "digest"),
        ("ollama", {"ollama_image": OLLAMA, "ollama_models_pvc": "state"}, "separate"),
        (
            "ollama",
            {"ollama_image": OLLAMA, "ollama_models_pvc": "m", "manifest": "../x.csv"},
            "plain",
        ),
    ],
)
def test_rejects_unsafe_or_incomplete_inputs(provider, kwargs, message):
    with pytest.raises(ValueError, match=message):
        render(provider, **kwargs)
