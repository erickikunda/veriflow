"""Render a namespaced CSV pipeline Job; never contacts a cluster or creates storage."""

import argparse
import ipaddress
import json
import re
from pathlib import Path

DNS_LABEL = r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?"
PINNED = r"[a-zA-Z0-9][a-zA-Z0-9./:_-]*@sha256:[a-f0-9]{64}"
TOOLCHAINS = {
    "general": [],
    "csharp": ["--joern-repair-dir", "/opt/veriflow/csharp-repair"],
    "rust": ["--rust-home", "/opt/rust"],
}
PROVIDERS = {"ollama", "anthropic", "openai"}
OLLAMA_PORT = 11434


def _check(namespace, name, image, pvcs, provider, toolchain, manifest):
    for value in (namespace, name, *pvcs.values()):
        if not re.fullmatch(DNS_LABEL, value):
            raise ValueError("Names must be DNS labels of at most 63 characters")
    if len(set(pvcs.values())) != len(pvcs):
        raise ValueError("Use separate input, reports and state PVCs")
    if not re.fullmatch(PINNED, image):
        raise ValueError("A registry image pinned by SHA-256 digest is required")
    if provider not in PROVIDERS or toolchain not in TOOLCHAINS:
        raise ValueError("Unsupported provider or toolchain")
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,99}\.csv", manifest):
        raise ValueError("Manifest must be a plain .csv file name at the input PVC root")


def _egress(provider, egress_cidrs):
    if provider == "ollama":
        # The sidecar is reached over loopback, which NetworkPolicy does not filter.
        return []
    if not egress_cidrs:
        raise ValueError("Live hosted providers require at least one --egress-cidr")
    blocks = [str(ipaddress.ip_network(cidr, strict=True)) for cidr in egress_cidrs]
    return [
        {
            "to": [
                {
                    "namespaceSelector": {
                        "matchLabels": {"kubernetes.io/metadata.name": "openshift-dns"}
                    }
                }
            ],
            "ports": [{"protocol": "UDP", "port": 5353}, {"protocol": "TCP", "port": 5353}]
            + [{"protocol": "UDP", "port": 53}, {"protocol": "TCP", "port": 53}],
        },
        {
            "to": [{"ipBlock": {"cidr": block}} for block in blocks],
            "ports": [{"protocol": "TCP", "port": 443}],
        },
    ]


def _restricted():
    return {
        "allowPrivilegeEscalation": False,
        "readOnlyRootFilesystem": True,
        "capabilities": {"drop": ["ALL"]},
    }


def bundle(
    namespace,
    name,
    image,
    input_pvc,
    reports_pvc,
    state_pvc,
    config_secret,
    provider,
    *,
    manifest="repos.csv",
    toolchain="general",
    api_key_secret=None,
    api_key_env=None,
    egress_cidrs=(),
    ollama_image=None,
    ollama_models_pvc=None,
    arch="arm64",
    deadline_seconds=86400,
    rescan_empty=False,
    reimport=False,
    llm_discovery=False,
    force_reimport=False,
    retry_unknown=False,
):
    pvcs = {"input": input_pvc, "reports": reports_pvc, "state": state_pvc}
    if provider == "ollama" and ollama_models_pvc:
        pvcs["models"] = ollama_models_pvc
    _check(namespace, name, image, pvcs, provider, toolchain, manifest)
    if not re.fullmatch(DNS_LABEL, config_secret):
        raise ValueError("Config secret must be a DNS label")
    if arch not in {"arm64", "amd64"} or not 600 <= deadline_seconds <= 7 * 86400:
        raise ValueError("Unsupported architecture or deadline")
    env = []
    if provider in {"anthropic", "openai"}:
        if not api_key_secret or not re.fullmatch(DNS_LABEL, api_key_secret):
            raise ValueError("Hosted providers require --api-key-secret")
        if not api_key_env or not re.fullmatch(r"[A-Z][A-Z0-9_]*", api_key_env):
            raise ValueError("Hosted providers require --api-key-env matching the config")
        env.append(
            {
                "name": api_key_env,
                "valueFrom": {"secretKeyRef": {"name": api_key_secret, "key": "api-key"}},
            }
        )
    elif ollama_image is None or not re.fullmatch(PINNED, ollama_image) or not ollama_models_pvc:
        raise ValueError("Ollama requires a digest-pinned --ollama-image and --ollama-models-pvc")
    egress = _egress(provider, list(egress_cidrs))
    args = [
        "--state-dir",
        "/state",
        "run-pipeline-from-csv",
        f"/input/{manifest}",
        "--input-root",
        "/input",
        "--advisory-config",
        "/config/advisory.json",
        "--joern-home",
        "/opt/joern-cli",
        "--output-dir",
        f"/reports/{name}",
        *TOOLCHAINS[toolchain],
    ]
    args += ["--rescan-empty"] if rescan_empty else []
    args += ["--reimport"] if reimport else []
    args += ["--force-reimport"] if force_reimport else []
    args += ["--retry-unknown"] if retry_unknown else []
    args += ["--llm-discovery"] if llm_discovery else []
    labels = {"app.kubernetes.io/name": "veriflow-pipeline", "veriflow-job": name}
    metadata = {"name": name, "namespace": namespace}
    volumes = [
        {"name": "input", "persistentVolumeClaim": {"claimName": input_pvc, "readOnly": True}},
        {"name": "reports", "persistentVolumeClaim": {"claimName": reports_pvc}},
        {"name": "state", "persistentVolumeClaim": {"claimName": state_pvc}},
        {"name": "config", "secret": {"secretName": config_secret, "defaultMode": 0o440}},
        {"name": "tmp", "emptyDir": {"sizeLimit": "4Gi"}},
        {"name": "work", "emptyDir": {"sizeLimit": "4Gi"}},
    ]
    sidecars = []
    if provider == "ollama":
        volumes += [
            {"name": "models", "persistentVolumeClaim": {"claimName": ollama_models_pvc}},
            {"name": "ollama-home", "emptyDir": {"sizeLimit": "1Gi"}},
            {"name": "ollama-tmp", "emptyDir": {"sizeLimit": "2Gi"}},
        ]
        # A native sidecar starts first and stops with the Job; models must already be pulled.
        sidecars.append(
            {
                "name": "ollama",
                "image": ollama_image,
                "imagePullPolicy": "IfNotPresent",
                "restartPolicy": "Always",
                "args": ["serve"],
                "env": [
                    {"name": "OLLAMA_HOST", "value": f"127.0.0.1:{OLLAMA_PORT}"},
                    {"name": "OLLAMA_MODELS", "value": "/models"},
                    {"name": "HOME", "value": "/home/ollama"},
                ],
                # Kubelet probes from the node; only an exec probe reaches the pod loopback.
                "startupProbe": {
                    "exec": {"command": ["ollama", "list"]},
                    "periodSeconds": 5,
                    "failureThreshold": 60,
                },
                "securityContext": _restricted(),
                "resources": {
                    "requests": {"cpu": "4", "memory": "12Gi"},
                    "limits": {"cpu": "8", "memory": "24Gi"},
                },
                "volumeMounts": [
                    {"name": "models", "mountPath": "/models", "readOnly": True},
                    {"name": "ollama-home", "mountPath": "/home/ollama"},
                    {"name": "ollama-tmp", "mountPath": "/tmp"},
                ],
            }
        )
    pod = {
        "serviceAccountName": name,
        "automountServiceAccountToken": False,
        "restartPolicy": "Never",
        "enableServiceLinks": False,
        "nodeSelector": {"kubernetes.io/arch": arch},
        "securityContext": {"runAsNonRoot": True, "seccompProfile": {"type": "RuntimeDefault"}},
        "containers": [
            {
                "name": "pipeline",
                "image": image,
                "imagePullPolicy": "IfNotPresent",
                "args": args,
                "env": env,
                "securityContext": _restricted(),
                "resources": {
                    "requests": {"cpu": "2", "memory": "6Gi", "ephemeral-storage": "2Gi"},
                    "limits": {"cpu": "4", "memory": "8Gi", "ephemeral-storage": "8Gi"},
                },
                "volumeMounts": [
                    {"name": "input", "mountPath": "/input", "readOnly": True},
                    {"name": "reports", "mountPath": "/reports"},
                    {"name": "state", "mountPath": "/state"},
                    {"name": "config", "mountPath": "/config", "readOnly": True},
                    {"name": "tmp", "mountPath": "/tmp"},
                    # The Joern base image sets HOME and WORKDIR to /work.
                    {"name": "work", "mountPath": "/work"},
                ],
            }
        ],
        "volumes": volumes,
    }
    if sidecars:
        pod["initContainers"] = sidecars
    return {
        "apiVersion": "v1",
        "kind": "List",
        "items": [
            {
                "apiVersion": "v1",
                "kind": "ServiceAccount",
                "metadata": metadata,
                "automountServiceAccountToken": False,
            },
            {
                "apiVersion": "networking.k8s.io/v1",
                "kind": "NetworkPolicy",
                "metadata": metadata,
                "spec": {
                    "podSelector": {"matchLabels": labels},
                    "policyTypes": ["Ingress", "Egress"],
                    "ingress": [],
                    "egress": egress,
                },
            },
            {
                "apiVersion": "batch/v1",
                "kind": "Job",
                "metadata": metadata,
                "spec": {
                    "backoffLimit": 0,
                    "activeDeadlineSeconds": deadline_seconds,
                    "parallelism": 1,
                    "completions": 1,
                    "template": {"metadata": {"labels": labels}, "spec": pod},
                },
            },
        ],
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for flag in (
        "namespace",
        "name",
        "image",
        "input-pvc",
        "reports-pvc",
        "state-pvc",
        "config-secret",
    ):
        parser.add_argument(f"--{flag}", required=True)
    parser.add_argument("--provider", choices=sorted(PROVIDERS), required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--manifest", default="repos.csv")
    parser.add_argument("--toolchain", choices=sorted(TOOLCHAINS), default="general")
    parser.add_argument("--api-key-secret")
    parser.add_argument("--api-key-env")
    parser.add_argument("--egress-cidr", action="append", default=[])
    parser.add_argument("--ollama-image")
    parser.add_argument("--ollama-models-pvc")
    parser.add_argument("--arch", choices=["arm64", "amd64"], default="arm64")
    parser.add_argument("--deadline-seconds", type=int, default=86400)
    parser.add_argument("--rescan-empty", action="store_true")
    parser.add_argument("--reimport", action="store_true")
    parser.add_argument("--llm-discovery", action="store_true")
    parser.add_argument("--force-reimport", action="store_true")
    parser.add_argument("--retry-unknown", action="store_true")
    args = parser.parse_args()
    data = bundle(
        args.namespace,
        args.name,
        args.image,
        args.input_pvc,
        args.reports_pvc,
        args.state_pvc,
        args.config_secret,
        args.provider,
        manifest=args.manifest,
        toolchain=args.toolchain,
        api_key_secret=args.api_key_secret,
        api_key_env=args.api_key_env,
        egress_cidrs=args.egress_cidr,
        ollama_image=args.ollama_image,
        ollama_models_pvc=args.ollama_models_pvc,
        arch=args.arch,
        deadline_seconds=args.deadline_seconds,
        rescan_empty=args.rescan_empty,
        reimport=args.reimport,
        llm_discovery=args.llm_discovery,
        force_reimport=args.force_reimport,
        retry_unknown=args.retry_unknown,
    )
    with args.output.open("x") as target:
        json.dump(data, target, indent=2)
        target.write("\n")


if __name__ == "__main__":
    main()
