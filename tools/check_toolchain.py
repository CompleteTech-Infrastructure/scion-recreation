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
import selectors
import signal
import subprocess
import sys
import threading
import time


ROOT = Path(__file__).resolve().parent.parent
COMMAND_TIMEOUT = 300
MAX_EVENT_BYTES = 1024 * 1024
MAX_TEST_BYTES = 64 * 1024 * 1024
CLEANUP_TIMEOUT = 2


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


def execute(command, consume, *, timeout=None, output_error="command output exceeded its byte limit"):
    """Own a POSIX process group, including writers outliving its leader.

    Read only ready, nonblocking pipes. Every exit kills the group and closes
    pipes without draining them; neither EOF nor descendant cooperation is
    required for cleanup. The direct child's status is preserved separately.
    """
    if os.name != "posix":
        raise BuildError("bounded process-group execution requires POSIX")
    timeout = COMMAND_TIMEOUT if timeout is None else timeout
    deadline = time.monotonic() + timeout
    watched = (signal.SIGINT, signal.SIGTERM, signal.SIGHUP) if threading.current_thread() is threading.main_thread() else ()
    handlers = {}
    interruption = []
    child = None
    group_terminated = False
    selector = selectors.DefaultSelector()

    def interrupted(signum, frame):
        # Defer unwinding until Popen has returned an owned child. Repeated
        # signals also cannot interrupt process-group cleanup.
        if not interruption:
            interruption.append(signum)

    def terminate_group():
        nonlocal group_terminated
        if group_terminated:
            return
        try:
            os.killpg(child.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        except PermissionError:
            # Darwin reports EPERM for a group containing only its zombie
            # leader. Reap that confirmed exit and retry once; a real
            # permission failure must still propagate. Other hosts retain
            # the waitable leader throughout group termination.
            if sys.platform != "darwin" or os.waitid(
                os.P_PID, child.pid, os.WEXITED | os.WNOHANG | os.WNOWAIT
            ) is None:
                raise
            child.wait(timeout=0)
            try:
                os.killpg(child.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
        group_terminated = True

    try:
        for signum in watched:
            handlers[signum] = signal.signal(signum, interrupted)
        try:
            child = subprocess.Popen(
                command, cwd=ROOT, env=environment(), stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                start_new_session=True,
            )
        except OSError as exc:
            raise BuildError(f"cannot execute {command[0]}: {exc}", 127) from exc
        for name, pipe in (("stdout", child.stdout), ("stderr", child.stderr)):
            os.set_blocking(pipe.fileno(), False)
            selector.register(pipe, selectors.EVENT_READ, name)
        totals = {"stdout": 0, "stderr": 0}
        status = None
        drain_deadline = None
        while selector.get_map() or status is None:
            if interruption:
                raise BuildError(f"command interrupted by signal {interruption[0]}", 128 + interruption[0])
            if status is None:
                # Keep the leader waitable until group cleanup, preventing its
                # PID/PGID from being reused while inherited writers remain.
                exited = os.waitid(os.P_PID, child.pid, os.WEXITED | os.WNOHANG | os.WNOWAIT)
                if exited is not None:
                    status = exited.si_status if exited.si_code == os.CLD_EXITED else -exited.si_status
                    terminate_group()
                    drain_deadline = time.monotonic() + CLEANUP_TIMEOUT
            remaining = deadline - time.monotonic()
            if drain_deadline is not None:
                remaining = min(remaining, drain_deadline - time.monotonic())
            if remaining <= 0:
                if status:
                    return status
                raise BuildError(f"command timed out after {timeout}s: {command[0]}", 124)
            # Some selector backends return immediately with no descriptors.
            # A child may close both pipes and continue running until timeout.
            if not selector.get_map():
                time.sleep(min(remaining, 0.05))
                continue
            for key, _ in selector.select(min(remaining, 0.05)):
                data = os.read(key.fd, 65536)
                if not data:
                    selector.unregister(key.fileobj)
                    continue
                totals[key.data] += len(data)
                if totals[key.data] > MAX_TEST_BYTES:
                    raise BuildError(output_error)
                consume(key.data, data)
        return status
    finally:
        try:
            if child is not None:
                try:
                    terminate_group()
                finally:
                    for pipe in (child.stdout, child.stderr):
                        if pipe is not None:
                            pipe.close()
                    # Never use an unbounded wait, even after SIGKILL.
                    try:
                        child.wait(timeout=CLEANUP_TIMEOUT)
                    except subprocess.TimeoutExpired as exc:
                        raise BuildError("process group cleanup timed out", 124) from exc
        finally:
            selector.close()
            for signum, handler in handlers.items():
                signal.signal(signum, handler)
            if interruption:
                raise BuildError(f"command interrupted by signal {interruption[0]}", 128 + interruption[0])


def run(command, *, capture=False, timeout=None):
    output = bytearray()

    def consume(name, data):
        if capture and name == "stdout":
            output.extend(data)
        else:
            stream = sys.stdout if name == "stdout" else sys.stderr
            stream.buffer.write(data)
            stream.buffer.flush()

    status = execute(command, consume, timeout=timeout)
    text = output.decode() if capture else None
    if status:
        if text:
            print(text, end="")
        raise BuildError(f"command failed ({status}): {command[0]}", status)
    return text


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
    active = set()
    passed = 0
    failed = False
    pending = bytearray()

    def event_line(line):
        nonlocal passed, failed
        if len(line) > MAX_EVENT_BYTES:
            raise BuildError("test JSON output exceeded its byte limit")
        sys.stdout.buffer.write(line)
        sys.stdout.buffer.flush()
        try:
            event = json.loads(line)
            if not isinstance(event, dict):
                raise ValueError("event must be an object")
        except (ValueError, UnicodeError) as exc:
            raise BuildError("invalid JSON in go test output") from exc
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

    def consume(name, data):
        if name == "stderr":
            sys.stderr.buffer.write(data)
            sys.stderr.buffer.flush()
            return
        pending.extend(data)
        while (end := pending.find(b"\n")) >= 0:
            line = bytes(pending[:end + 1])
            del pending[:end + 1]
            event_line(line)
        if len(pending) > MAX_EVENT_BYTES:
            raise BuildError("test JSON output exceeded its byte limit")

    status = execute(command, consume, output_error="test JSON output exceeded its byte limit")
    if pending:
        event_line(bytes(pending))
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
