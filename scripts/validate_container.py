"""Run language fixture suites in a restricted Linux container and export reports."""

import argparse
import json
import subprocess
import time
import uuid
from pathlib import Path

QUERY = (
    "/opt/codeql-bundle/codeql/qlpacks/codeql/python-queries/1.8.10/"
    "Security/CWE-094/CodeInjection.ql"
)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("output", type=Path, help="New local output directory")
    parser.add_argument("--image", default="veriflow:linux-poc")
    parser.add_argument(
        "--suite",
        choices=[
            "python",
            "joern",
            "joern-csharp",
            "joern-csharp-advisory",
            "joern-python",
            "joern-pipeline",
            "joern-flask",
            "joern-flask-advisory",
            "joern-go-http",
            "joern-go-advisory",
            "joern-spring-evidence",
            "joern-spring-advisory",
            "joern-workflow-advisory",
            "joern-argv-c",
            "joern-argv-advisory-c",
            "joern-argv-advisory-cpp",
            "joern-argv-cpp",
            "joern-express-javascript",
            "joern-express-advisory-javascript",
            "joern-express-advisory-typescript",
            "joern-express-typescript",
            "joern-go",
            "joern-rust",
            "joern-rust-env",
            "joern-rust-wide",
            "joern-rust-advisory",
            "joern-c",
            "joern-cpp",
            "joern-javascript",
            "joern-typescript",
            "java",
            "spring",
            "csharp",
            "csharp-classic",
            "csharp-core",
            "csharp-minimal",
            "csharp-webapi",
            "csharp-mvc",
            "javascript",
            "typescript",
        ],
        default="python",
    )
    parser.add_argument("--project-layout", choices=["flat", "maven", "gradle"], default="flat")
    args = parser.parse_args()
    if args.suite not in ("java", "spring") and args.project_layout != "flat":
        parser.error("Project layouts apply only to Java/Spring")
    if args.suite in {"joern-javascript", "joern-typescript"}:
        language = args.suite.removeprefix("joern-")
        scan = (
            "/opt/veriflow-venv/bin/python "
            "/opt/veriflow/scripts/validate_joern_javascript_discovery.py "
            f"--language {language} --joern-home /opt/joern-cli --output /work/acceptance"
        )
        results_file = "case-results.json"
    elif args.suite in {"joern-c", "joern-cpp"}:
        language = args.suite.removeprefix("joern-")
        scan = (
            "/opt/veriflow-venv/bin/python "
            "/opt/veriflow/scripts/validate_joern_c_family_discovery.py "
            f"--language {language} --joern-home /opt/joern-cli --output /work/acceptance"
        )
        results_file = "case-results.json"
    elif args.suite in {
        "joern-express-javascript",
        "joern-express-typescript",
    }:
        language = args.suite.removeprefix("joern-express-")
        scan = (
            "/opt/veriflow-venv/bin/python /opt/veriflow/scripts/validate_joern_express.py "
            f"--language {language} --joern-home /opt/joern-cli --output /work/acceptance"
        )
        results_file = "case-results.json"
    elif args.suite in {"joern-express-advisory-javascript", "joern-express-advisory-typescript"}:
        language = args.suite.removeprefix("joern-express-advisory-")
        scan = (
            "/opt/veriflow-venv/bin/python "
            "/opt/veriflow/scripts/validate_joern_express_advisory.py "
            f"--language {language} --joern-home /opt/joern-cli --output /work/acceptance"
        )
        results_file = "case-results.json"
    elif args.suite in {"joern-argv-advisory-c", "joern-argv-advisory-cpp"}:
        language = args.suite.removeprefix("joern-argv-advisory-")
        scan = (
            "/opt/veriflow-venv/bin/python "
            "/opt/veriflow/scripts/validate_joern_argv_advisory.py "
            f"--language {language} --joern-home /opt/joern-cli --output /work/acceptance"
        )
        results_file = "case-results.json"
    elif args.suite in {"joern-argv-c", "joern-argv-cpp"}:
        language = args.suite.removeprefix("joern-argv-")
        scan = (
            "/opt/veriflow-venv/bin/python /opt/veriflow/scripts/validate_joern_argv.py "
            f"--language {language} --joern-home /opt/joern-cli --output /work/acceptance"
        )
        results_file = "case-results.json"
    elif args.suite in {
        "joern-pipeline",
        "joern-flask",
        "joern-flask-advisory",
        "joern-go-http",
        "joern-go-advisory",
        "joern-spring-evidence",
        "joern-spring-advisory",
        "joern-workflow-advisory",
    }:
        profile = args.suite.removeprefix("joern-").replace("-", "_")
        scan = (
            f"/opt/veriflow-venv/bin/python /opt/veriflow/scripts/validate_joern_{profile}.py "
            "--joern-home /opt/joern-cli --output /work/acceptance"
        )
        results_file = "case-results.json"
    elif args.suite == "joern-csharp-advisory":
        scan = (
            "/opt/veriflow-venv/bin/python "
            "/opt/veriflow/scripts/validate_joern_csharp_advisory.py "
            "--joern-home /opt/joern-cli --repair-dir /opt/veriflow/csharp-repair "
            "--output /work/acceptance"
        )
        results_file = "case-results.json"
    elif args.suite == "joern-rust-advisory":
        scan = (
            "/opt/veriflow-venv/bin/python "
            "/opt/veriflow/scripts/validate_joern_rust_advisory.py "
            "--joern-home /opt/joern-cli --rust-home /opt/rust --output /work/acceptance"
        )
        results_file = "case-results.json"
    elif args.suite == "joern-rust-env":
        scan = (
            "/opt/veriflow-venv/bin/python /opt/veriflow/scripts/validate_joern_rust_env.py "
            "--joern-home /opt/joern-cli --rust-home /opt/rust --output /work/acceptance"
        )
        results_file = "case-results.json"
    elif args.suite == "joern-rust-wide":
        scan = (
            "/opt/veriflow-venv/bin/python /opt/veriflow/scripts/validate_joern_rust_wide.py "
            "--joern-home /opt/joern-cli --rust-home /opt/rust --output /work/acceptance"
        )
        results_file = "wide-gate.json"
    elif args.suite == "joern-rust":
        scan = (
            "/opt/veriflow-venv/bin/python "
            "/opt/veriflow/scripts/validate_joern_rust_discovery.py "
            "--joern-home /opt/joern-cli --rust-home /opt/rust --output /work/acceptance"
        )
        results_file = "case-results.json"
    elif args.suite in {"joern-python", "joern-go"}:
        language = args.suite.removeprefix("joern-")
        scan = (
            "/opt/veriflow-venv/bin/python "
            f"/opt/veriflow/scripts/validate_joern_{language}_discovery.py "
            "--joern-home /opt/joern-cli --output /work/acceptance"
        )
        results_file = "case-results.json"
    elif args.suite == "joern-csharp":
        scan = "/opt/veriflow-venv/bin/python /opt/veriflow/joern_csharp_acceptance.py"
        results_file = "joern-csharp-results.json"
    elif args.suite == "joern":
        scan = "/opt/veriflow-venv/bin/python /opt/veriflow/joern_acceptance.py"
        results_file = "joern-results.json"  # Joern writes case-results directly to /reports.
    elif args.suite == "python":
        scan = f"veriflow acceptance-run /work/acceptance {QUERY} --timeout 300"
        results_file = "acceptance.json"
    elif args.suite in ("javascript", "typescript"):
        query = (
            "/opt/codeql-bundle/codeql/qlpacks/codeql/javascript-queries/2.4.5/"
            "Security/CWE-094/CodeInjection.ql"
        )
        scan = (
            f"/opt/veriflow-venv/bin/python /opt/veriflow/scripts/validate_{args.suite}.py "
            f"{query} /work/acceptance"
        )
        results_file = "validation.json"
    elif args.suite.startswith("csharp"):
        script = args.suite.replace("-", "_")
        query = (
            "/opt/codeql-bundle/codeql/qlpacks/codeql/csharp-queries/1.9.3/"
            "Security Features/CWE-089/SqlInjection.ql"
        )
        profile = (
            "core-profile.json"
            if args.suite in ("csharp-core", "csharp-minimal")
            else "profile.json"
        )
        if args.suite in ("csharp-webapi", "csharp-mvc"):
            profile = args.suite.removeprefix("csharp-") + "-profile.json"
        scan = (
            f"/opt/veriflow-venv/bin/python /opt/veriflow/scripts/validate_{script}.py "
            f"'{query}' /work/acceptance --csharp-dependency-profile "
            f"/opt/veriflow/csharp-dependencies/{profile}"
        )
        results_file = "validation.json"
    else:
        query_name = "SqlTainted.ql" if args.suite == "spring" else "SqlConcatenated.ql"
        query = (
            "/opt/codeql-bundle/codeql/qlpacks/codeql/java-queries/1.11.10/Security/CWE/CWE-089/"
            + query_name
        )
        scan = (
            f"/opt/veriflow-venv/bin/python /opt/veriflow/scripts/validate_{args.suite}.py "
            f"{query} /work/acceptance"
        )
        if args.suite == "spring":
            scan += " --java-dependency-profile /opt/veriflow/dependencies/java-profile.json"
        if args.project_layout != "flat":
            scan += f" --java-profile source-only --project-layout {args.project_layout}"
        results_file = "validation.json"
    output = args.output.resolve()
    output.mkdir(parents=True, exist_ok=False)
    name = "veriflow-smoke-" + uuid.uuid4().hex[:12]
    inspected = json.loads(subprocess.check_output(["docker", "image", "inspect", args.image]))[0]
    if inspected["Architecture"] != "arm64" or inspected["Os"] != "linux":
        raise RuntimeError("This acceptance recipe requires a Linux ARM64 image")
    image = inspected["Id"]  # Run the inspected immutable local image ID, not a moving tag.
    command = [
        "docker",
        "create",
        "--name",
        name,
        "--platform",
        "linux/arm64",
        "--user",
        "1000710000:0",
        "--read-only",
        "--network",
        "none",
        "--cap-drop",
        "ALL",
        "--security-opt",
        "no-new-privileges:true",
        "--cpus",
        "2",
        "--memory",
        "4g",
        "--pids-limit",
        "256",
        "--tmpfs",
        "/work:rw,exec,nosuid,nodev,size=1073741824,mode=0770,gid=0",
        "--tmpfs",
        "/tmp:rw,exec,nosuid,nodev,size=1073741824,mode=1777",
        "--mount",
        f"type=bind,src={output},dst=/reports",
        "--entrypoint",
        "/bin/bash",
        image,
        "-euc",
        "mkdir /reports/diagnostics\n"
        "export_artifacts() {\n"
        'find /work -name "*.log" '
        "-exec cp --parents {} /reports/diagnostics/ \\; || true\n"
        f"if [ -f /work/acceptance/{results_file} ]; then "
        f"cp /work/acceptance/{results_file} /reports/case-results.json; fi\n"
        "if [ -d /work/acceptance ]; then "
        "find /work/acceptance -maxdepth 1 -type f "
        "\\( -name '*.html' -o -name '*.csv' -o -name '*.md' -o -name '*.json' \\) "
        "-exec cp {} /reports/ \\;\nfi\n"
        "}\ntrap export_artifacts EXIT\n"
        "/opt/veriflow-venv/bin/python /opt/veriflow/runtime_probe.py > /reports/runtime.json\n"
        "/opt/veriflow-venv/bin/python -m pip inspect > /reports/python-packages.json\n"
        "rpm -qa | sort > /reports/os-packages.txt\n"
        "java -version > /reports/java-version.txt 2>&1\n"
        f"{scan} > /reports/cli.log 2>&1\n",
    ]
    subprocess.run(command, check=True, capture_output=True)
    started = time.monotonic()
    try:
        (output / "container-config.json").write_bytes(
            subprocess.check_output(["docker", "inspect", name])
        )
        try:
            result = subprocess.run(["docker", "start", "-a", name], timeout=900)
        except subprocess.TimeoutExpired:
            subprocess.run(["docker", "kill", name], check=False, capture_output=True)
            raise
        finally:
            state = json.loads(subprocess.check_output(["docker", "inspect", name]))[0]["State"]
            (output / "container-state.json").write_text(json.dumps(state, indent=2))
        passed = result.returncode == 0 and (output / "case-results.json").exists()
        if passed:
            cases = json.loads((output / "case-results.json").read_text())
            passed = (
                cases["passed"]
                if args.suite == "python"
                else len(cases)
                == (
                    10
                    if args.suite == "joern-csharp-advisory"
                    else 7
                    if args.suite
                    in {"joern-spring-evidence", "joern-spring-advisory", "joern-workflow-advisory"}
                    else 9
                    if args.suite
                    in {
                        "joern-go-http",
                        "joern-go-advisory",
                        "joern-rust-env",
                        "joern-rust-advisory",
                    }
                    else 8
                    if args.suite
                    in {
                        "joern-flask",
                        "joern-flask-advisory",
                        "joern-express-javascript",
                        "joern-express-advisory-javascript",
                        "joern-express-advisory-typescript",
                        "joern-express-typescript",
                        "joern-argv-c",
                        "joern-argv-advisory-c",
                        "joern-argv-advisory-cpp",
                        "joern-argv-cpp",
                    }
                    else 5
                    if args.suite
                    in {
                        "joern-c",
                        "joern-cpp",
                        "joern-python",
                        "joern-pipeline",
                        "joern-go",
                        "joern-rust",
                        "joern-javascript",
                        "joern-typescript",
                    }
                    else 22
                    if args.suite == "joern-csharp"
                    else 9
                    if args.suite == "joern"
                    else 4
                    if args.suite == "spring"
                    else 2
                )
                and all(case["passed"] for case in cases)
            )
        summary = dict(
            passed=passed,
            image_id=image,
            architecture=inspected["Architecture"],
            elapsed_seconds=round(time.monotonic() - started, 3),
            ocp_qualified=False,
            scope="Local restricted Linux fixture validation",
            suite=args.suite,
            project_layout=args.project_layout,
        )
        (output / "validation.json").write_text(json.dumps(summary, indent=2))
        print(json.dumps(summary))
        if not passed:
            raise SystemExit("Container acceptance failed; inspect output diagnostics")
    finally:
        subprocess.run(["docker", "rm", "--force", name], check=False, capture_output=True)


if __name__ == "__main__":
    main()
