"""Verify installed pins and run the bounded local Go build/test entrypoints.

No install, download, provider selection, generation or dependency update occurs.
The lock records optional future tools separately; only tools required for the
selected action are checked. Override executable paths through Make variables.
"""

import argparse
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import threading


ROOT = Path(__file__).resolve().parent.parent
COMMAND_TIMEOUT = 300
MAX_EVENT_BYTES = 1024 * 1024
MAX_TEST_BYTES = 64 * 1024 * 1024


class BuildError(Exception):
    def __init__(self, message, code=1):
        super().__init__(message)
        self.code = code if code > 0 else 128 - code


def environment():
    env = os.environ.copy()
    env.update(
        GOTOOLCHAIN="local", GOPROXY="off", GOSUMDB="off", GOWORK="off",
        GOENV="off", GOFLAGS="-mod=readonly", GO111MODULE="on",
        GOPRIVATE="", GONOPROXY="none", GONOSUMDB="none", GOVCS="*:off",
    )
    return env


def run(command, *, capture=False, timeout=COMMAND_TIMEOUT):
    try:
        result = subprocess.run(
            command, cwd=ROOT, env=environment(), stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE if capture else None,
            stderr=subprocess.PIPE if capture else None,
            text=True, timeout=timeout, check=False,
        )
    except OSError as exc:
        raise BuildError(f"cannot execute {command[0]}: {exc}", 127) from exc
    except subprocess.TimeoutExpired as exc:
        raise BuildError(f"command timed out after {timeout}s: {command[0]}", 124) from exc
    if capture and result.stderr:
        print(result.stderr, file=sys.stderr, end="")
    if result.returncode:
        if capture and result.stdout:
            print(result.stdout, end="")
        raise BuildError(f"command failed ({result.returncode}): {command[0]}", result.returncode)
    return result.stdout if capture else None


def verify(action, go, protoc):
    lock = json.loads((ROOT / "toolchain.lock.json").read_text())
    if lock["schema_version"] != 1:
        raise BuildError("unsupported toolchain lock schema")
    tools = lock["tools"]
    python_version = ".".join(map(str, sys.version_info[:3]))
    if python_version != tools["python"]["version"] or sys.version_info.releaselevel != "final":
        raise BuildError(f"python mismatch: expected {tools['python']['version']}, observed {sys.version.split()[0]}")
    print(f"python: {python_version} ({sys.executable})", flush=True)
    checks = {
        "go": ([go, "version"], r"go version go([^\s]+) \S+"),
        "protoc": ([protoc, "--version"], r"libprotoc ([^\s]+)"),
    }
    for name, (command, pattern) in checks.items():
        if action not in tools[name]["required_for"]:
            continue
        output = run(command, capture=True, timeout=15).strip()
        match = re.fullmatch(pattern, output)
        expected = tools[name]["version"]
        if match is None or match.group(1) != expected:
            raise BuildError(f"{name} mismatch: expected {expected}, observed {output!r}")
        print(f"{name}: {expected} ({command[0]})", flush=True)


def packages(go):
    output = run([go, "list", "./..."], capture=True)
    selected = output.splitlines()
    if not selected:
        raise BuildError("no Go packages selected; build/test cannot pass an empty package set")
    print(f"selected Go packages: {len(selected)}", flush=True)


def test(go):
    command = [go, "test", "-json", "-count=1", "-timeout=120s", "./..."]
    try:
        child = subprocess.Popen(
            command, cwd=ROOT, env=environment(), stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
        )
    except OSError as exc:
        raise BuildError(f"cannot execute {go}: {exc}", 127) from exc
    expired = threading.Event()

    def timeout():
        expired.set()
        child.kill()

    timer = threading.Timer(COMMAND_TIMEOUT, timeout)
    active = set()
    passed = 0
    failed = False
    total_bytes = 0
    error = None
    timer.start()
    try:
        while True:
            line = child.stdout.readline(MAX_EVENT_BYTES + 1)
            if not line:
                break
            total_bytes += len(line)
            if len(line) > MAX_EVENT_BYTES or total_bytes > MAX_TEST_BYTES:
                error = "test JSON output exceeded its byte limit"
                child.kill()
                break
            sys.stdout.buffer.write(line)
            sys.stdout.buffer.flush()
            try:
                event = json.loads(line)
                if not isinstance(event, dict):
                    raise ValueError("event must be an object")
            except (ValueError, UnicodeError):
                error = "invalid JSON in go test output"
                child.kill()
                break
            action = event.get("Action")
            name = event.get("Test")
            key = (event.get("Package"), name)
            if action == "fail":
                failed = True
            if name and action == "run":
                active.add(key)
            elif name and action in ("pass", "skip", "fail"):
                if action == "pass" and key in active:
                    passed += 1
                active.discard(key)
        status = child.wait()
    finally:
        timer.cancel()
        child.stdout.close()
        if child.poll() is None:
            child.kill()
            child.wait()
    if expired.is_set():
        raise BuildError(f"go test timed out after {COMMAND_TIMEOUT}s", 124)
    if error:
        raise BuildError(error)
    if status:
        raise BuildError(f"go test failed ({status})", status)
    if failed or active:
        raise BuildError("go test emitted failed or unfinished test events")
    if not passed:
        raise BuildError("zero named tests executed successfully; empty or skipped-only tests cannot pass")
    print(f"named tests executed successfully: {passed}", flush=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=("check", "build", "test"))
    parser.add_argument("--go", default=os.environ.get("GO", "go"))
    parser.add_argument("--protoc", default=os.environ.get("PROTOC", "protoc"))
    args = parser.parse_args()
    verify(args.action, args.go, args.protoc)
    if args.action == "check":
        return
    packages(args.go)
    if args.action == "build":
        # Compile libraries and commands without writing binaries into the tree.
        # Go treats the platform's null device as a discard target for all packages.
        run([args.go, "build", "-trimpath", "-buildvcs=false", "-o", os.devnull, "./..."])
    else:
        test(args.go)


if __name__ == "__main__":
    try:
        main()
    except (BuildError, OSError, ValueError, KeyError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        sys.exit(exc.code if isinstance(exc, BuildError) else 1)
