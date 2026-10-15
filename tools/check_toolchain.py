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
import socket
import struct
import subprocess
import sys
import threading
import time


ROOT = Path(__file__).resolve().parent.parent
COMMAND_TIMEOUT = 300
MAX_EVENT_BYTES = 1024 * 1024
MAX_TEST_BYTES = 64 * 1024 * 1024
CLEANUP_TIMEOUT = 2
OUTPUT_TIMEOUT = 2
OUTPUT_CHUNK = 65536
_output = threading.local()

# Only this disposable process writes inherited output descriptors. The
# controller never changes their shared file-status flags or buffers output in
# Python's standard streams. Acknowledgement means every byte was written.
_WRITER = """
import os, socket, struct, sys
s = socket.socket(fileno=int(sys.argv[1]))
def read(n):
    b = bytearray()
    while len(b) < n:
        part = s.recv(n - len(b))
        if not part:
            os._exit(74)
        b.extend(part)
    return b
try:
    while True:
        fd, size = struct.unpack('!BI', read(5))
        if fd not in (1, 2) or size > 65536:
            os._exit(74)
        data = read(size)
        while data:
            n = os.write(fd, data)
            if n <= 0:
                os._exit(74)
            del data[:n]
        s.sendall(b'1')
except BaseException:
    os._exit(74)
"""


class BuildError(Exception):
    def __init__(self, message, code=1):
        super().__init__(message)
        self.code = code if code > 0 else 128 - code


class Output:
    """One bounded in-flight chunk; no threads and no shutdown flush."""

    def __init__(self, deadline, interruption):
        self.deadline = deadline
        self.interruption = interruption
        self.child = None
        self.sock = None

    def write(self, name, data):
        if not data:
            return
        if self.child is None:
            self.sock, peer = socket.socketpair()
            try:
                self.child = subprocess.Popen(
                    [sys.executable, '-I', '-c', _WRITER, str(peer.fileno())],
                    stdin=subprocess.DEVNULL, stdout=sys.stdout, stderr=sys.stderr,
                    pass_fds=(peer.fileno(),), start_new_session=True,
                )
            finally:
                peer.close()
            self.sock.setblocking(False)
        for start in range(0, len(data), OUTPUT_CHUNK):
            packet = memoryview(struct.pack('!BI', 1 if name == 'stdout' else 2,
                                           len(data[start:start + OUTPUT_CHUNK]))
                                + data[start:start + OUTPUT_CHUNK])
            end = min(self.deadline, time.monotonic() + OUTPUT_TIMEOUT)
            with selectors.DefaultSelector() as ready:
                ready.register(self.sock, selectors.EVENT_WRITE)
                while True:
                    if self.interruption:
                        sig = self.interruption[0]
                        raise BuildError(f'command interrupted by signal {sig}', 128 + sig)
                    remaining = end - time.monotonic()
                    if remaining <= 0:
                        raise BuildError(f'{name} output delivery timed out', 124)
                    if not ready.select(min(remaining, 0.05)):
                        continue
                    try:
                        if packet:
                            sent = self.sock.send(packet)
                            if sent == 0:
                                raise OSError('output writer closed')
                            packet = packet[sent:]
                            if not packet:
                                ready.modify(self.sock, selectors.EVENT_READ)
                        else:
                            if self.sock.recv(1) != b'1':
                                raise OSError('output writer did not acknowledge delivery')
                            break
                    except BlockingIOError:
                        continue
                    except OSError as exc:
                        raise BuildError(f'cannot deliver {name} output: {exc}', 74) from exc

    def close(self):
        if self.sock is not None:
            self.sock.close()
        if self.child is not None:
            # This trusted writer never spawns descendants. Keep it waitable
            # until this exact-PID kill, so PID reuse cannot target a stranger.
            try:
                os.kill(self.child.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            try:
                self.child.wait(timeout=CLEANUP_TIMEOUT)
            except subprocess.TimeoutExpired as exc:
                raise BuildError('output writer cleanup timed out', 124) from exc


def emit(name, data):
    sink = getattr(_output, 'sink', None)
    if sink is not None:
        sink.write(name, data)
        return
    # Pin/status/error messages are bounded too, including the final error
    # path when the consumer has already closed its descriptor.
    interruption = []
    handlers = {}
    sink = Output(time.monotonic() + OUTPUT_TIMEOUT, interruption)
    try:
        if threading.current_thread() is threading.main_thread():
            for sig in (signal.SIGINT, signal.SIGTERM, signal.SIGHUP):
                handlers[sig] = signal.signal(sig, lambda signum, frame: interruption.append(signum))
        sink.write(name, data)
    finally:
        try:
            sink.close()
        finally:
            for sig, handler in handlers.items():
                signal.signal(sig, handler)
            if interruption:
                sig = interruption[0]
                raise BuildError(f'command interrupted by signal {sig}', 128 + sig)


def message(text, name='stdout'):
    emit(name, (text + '\n').encode())


def environment():
    env = os.environ.copy()
    env.update(
        GOTOOLCHAIN="local", GOPROXY="off", GOSUMDB="off", GOWORK="off",
        GOENV="off", GOFLAGS="-mod=readonly", GO111MODULE="on",
        GOPRIVATE="", GONOPROXY="none", GONOSUMDB="none", GOVCS="*:off",
    )
    return env


def execute(command, consume, *, timeout=None, output_error="command output exceeded its byte limit", on_complete=None):
    """Own a POSIX process group, including writers outliving its leader.

    Read only ready, nonblocking pipes. Every exit kills the group and closes
    pipes without draining them; neither EOF nor descendant cooperation is
    required for cleanup. The direct child's status is preserved separately.
    Internal callbacks parse bounded records and use emit() for external I/O;
    arbitrary blocking callbacks are not a supported supervision boundary.
    """
    if os.name != "posix":
        raise BuildError("bounded process-group execution requires POSIX")
    timeout = COMMAND_TIMEOUT if timeout is None else timeout
    deadline = time.monotonic() + timeout
    watched = (signal.SIGINT, signal.SIGTERM, signal.SIGHUP) if threading.current_thread() is threading.main_thread() else ()
    handlers = {}
    interruption = []
    child = None
    status = None
    group_terminated = False
    selector = selectors.DefaultSelector()
    previous_output = getattr(_output, 'sink', None)
    sink = Output(deadline, interruption)
    _output.sink = sink

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
                    sink.deadline = min(deadline, drain_deadline)
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
        if not status and on_complete is not None:
            if time.monotonic() >= sink.deadline:
                raise BuildError(f"command timed out after {timeout}s: {command[0]}", 124)
            on_complete()
        return status
    except (BuildError, OSError, ValueError):
        # A known command failure retains its exact status even if its last
        # output cannot be delivered. Undelivered output can never make a
        # successful command pass. Interruption remains an interruption.
        if child is not None and not interruption:
            if status is None:
                exited = os.waitid(os.P_PID, child.pid, os.WEXITED | os.WNOHANG | os.WNOWAIT)
                if exited is not None:
                    status = exited.si_status if exited.si_code == os.CLD_EXITED else -exited.si_status
            if status:
                return status
        raise
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
            try:
                sink.close()
            finally:
                _output.sink = previous_output
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
            emit(name, data)

    status = execute(command, consume, timeout=timeout)
    if status:
        # Captured diagnostics are best effort only after a known failure;
        # their delivery failure must not replace the command's exit status.
        if output:
            try:
                emit('stdout', bytes(output))
            except (BuildError, OSError, ValueError):
                pass
        raise BuildError(f"command failed ({status}): {command[0]}", status)
    return output.decode() if capture else None


def verify(action, go, protoc):
    lock = json.loads((ROOT / "toolchain.lock.json").read_text())
    if lock["schema_version"] != 1:
        raise BuildError("unsupported toolchain lock schema")
    tools = lock["tools"]
    python_version = ".".join(map(str, sys.version_info[:3]))
    if python_version != tools["python"]["version"] or sys.version_info.releaselevel != "final":
        raise BuildError(f"python mismatch: expected {tools['python']['version']}, observed {sys.version.split()[0]}")
    message(f"python: {python_version} ({sys.executable})")
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
        message(f"{name}: {expected} ({command[0]})")


def packages(go):
    output = run([go, "list", "./..."], capture=True)
    selected = output.splitlines()
    if not selected:
        raise BuildError("no Go packages selected; build/test cannot pass an empty package set")
    message(f"selected Go packages: {len(selected)}")


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
        emit('stdout', line)
        try:
            event = json.loads(line)
            if not isinstance(event, dict):
                raise ValueError("event must be an object")
            # This entrypoint consumes `go test -json ./...`, whose events
            # identify their package (unlike standalone test2json input).
            if event.get('Action') not in (
                'start', 'run', 'pause', 'cont', 'pass', 'bench', 'fail', 'output', 'skip'
            ) or not isinstance(event.get('Package'), str) or not event['Package'] or any(
                key in event and not isinstance(event[key], str)
                for key in ('Test', 'Output', 'OutputType', 'FailedBuild', 'Time')
            ):
                raise ValueError("invalid event field type")
        except (ValueError, UnicodeError, RecursionError) as exc:
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
            emit('stderr', data)
            return
        pending.extend(data)
        while (end := pending.find(b"\n")) >= 0:
            line = bytes(pending[:end + 1])
            del pending[:end + 1]
            event_line(line)
        if len(pending) > MAX_EVENT_BYTES:
            raise BuildError("test JSON output exceeded its byte limit")

    def finish():
        if pending:
            event_line(bytes(pending))

    status = execute(command, consume, output_error="test JSON output exceeded its byte limit", on_complete=finish)
    if status:
        raise BuildError(f"go test failed ({status})", status)
    if failed or active:
        raise BuildError("go test emitted failed or unfinished test events")
    if not passed:
        raise BuildError("zero named tests executed successfully; empty or skipped-only tests cannot pass")
    message(f"named tests executed successfully: {passed}")


def main():
    class Parser(argparse.ArgumentParser):
        def _print_message(self, text, file=None):
            if text:
                emit('stderr' if file is sys.stderr else 'stdout', text.encode())

    parser = Parser(description=__doc__)
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
        try:
            message(f"error: {exc}", 'stderr')
        except (BuildError, OSError, ValueError):
            pass
        sys.exit(exc.code if isinstance(exc, BuildError) else 1)
