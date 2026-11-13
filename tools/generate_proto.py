"""Generate/check the accepted native and companion workflow Go bindings offline.

Run with the locked Python, Go and protoc (overrides: --go / --protoc).
`generate` publishes only the seven declared files after staging and compilation;
`check` never writes the source tree. Neither command implements RPC behavior.
Schema changes require a separately reviewed update to ACCEPTED, not auto-acceptance.
"""

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parent.parent
ACCEPTED = {
    "grants": "1c967ca1e7298fc0459059fc02cd7531faff1e1529be13faea2c10b32b55ac8c",
    "control": "50a0b0fd5c8de31e444afb4d605a67bb83681e2dea8f2e6ca09982df68c19d2e",
    "objects": "4383168af354606172fe8b7126b3b8d75391757bca356130df406af116871338",
    "workflows": "b561481181853f8e6a5c474314a01eeb131647fd3eadf2754ae460d803d4a7ed",
}
PACKAGES = {"grants": ("common", "commonv1"),
            "control": ("control", "controlv1"),
            "objects": ("objects", "objectsv1"),
            "workflows": ("workflows", "workflowsv1")}
OUTPUTS = (
    "api/gen/common/v1/grants.pb.go",
    "api/gen/control/v1/control.pb.go",
    "api/gen/control/v1/control_grpc.pb.go",
    "api/gen/objects/v1/objects.pb.go",
    "api/gen/objects/v1/objects_grpc.pb.go",
    "api/gen/workflows/v1/workflows.pb.go",
    "api/gen/workflows/v1/workflows_grpc.pb.go",
)

# Separate protoc descriptor-set production is compared with Go runtime
# reflection, including nested messages, presence, oneofs, enums and services.
# No schema parser or generated source-text matching substitutes for reflection.
REFLECT = r'''
package main
import (
    "fmt"
    "os"
    common "canopy.local/canopy/api/gen/common/v1"
    control "canopy.local/canopy/api/gen/control/v1"
    objects "canopy.local/canopy/api/gen/objects/v1"
    workflows "canopy.local/canopy/api/gen/workflows/v1"
    "google.golang.org/protobuf/proto"
    "google.golang.org/protobuf/reflect/protodesc"
    "google.golang.org/protobuf/reflect/protoreflect"
    "google.golang.org/protobuf/reflect/protoregistry"
    "google.golang.org/protobuf/types/descriptorpb"
)
func main() {
    data, err := os.ReadFile(os.Args[1]); must(err)
    set := new(descriptorpb.FileDescriptorSet); must(proto.Unmarshal(data, set))
    files := []protoreflect.FileDescriptor{common.File_api_proto_grants_proto,
        control.File_api_proto_control_proto, objects.File_api_proto_objects_proto,
        workflows.File_api_proto_workflows_proto}
    if len(set.File) != len(files) { panic("descriptor file count") }
    messages, fields, services, methods, shared := 0, 0, 0, 0, 0
    var walk func(protoreflect.MessageDescriptors)
    walk = func(ms protoreflect.MessageDescriptors) {
        for i := 0; i < ms.Len(); i++ {
            m := ms.Get(i); messages++
            for j := 0; j < m.Fields().Len(); j++ {
                f := m.Fields().Get(j); fields++
                if f.Message() != nil && f.Message().ParentFile() != m.ParentFile() {
                    d, e := protoregistry.GlobalFiles.FindDescriptorByName(f.Message().FullName())
                    must(e)
                    if d != f.Message() { panic("shared descriptor identity") }
                    shared++
                }
            }
            walk(m.Messages())
        }
    }
    for _, f := range files {
        var expected *descriptorpb.FileDescriptorProto
        for _, d := range set.File { if d.GetName() == f.Path() { expected = d } }
        if expected == nil || !proto.Equal(expected, protodesc.ToFileDescriptorProto(f)) {
            panic("descriptor mismatch: " + f.Path())
        }
        walk(f.Messages()); services += f.Services().Len()
        for i := 0; i < f.Services().Len(); i++ { methods += f.Services().Get(i).Methods().Len() }
    }
    if shared == 0 || methods == 0 { panic("missing shared references or RPCs") }
    fmt.Printf("reflected %d messages, %d fields, %d services, %d methods, %d shared references\n",
        messages, fields, services, methods, shared)
}
func must(err error) { if err != nil { panic(err) } }
'''


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def environment():
    env = os.environ.copy()
    env.update(GOTOOLCHAIN="local", GOPROXY="off", GOSUMDB="off", GOWORK="off",
               GOENV="off", GOFLAGS="-mod=readonly", GO111MODULE="on",
               GOPRIVATE="", GONOPROXY="none", GONOSUMDB="none", GOVCS="*:off",
               GOMAXPROCS="2", CGO_ENABLED="0")
    return env


def run(command, cwd=ROOT):
    result = subprocess.run(command, cwd=cwd, env=environment(), check=True,
                            stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE, timeout=300)
    if result.stderr:
        sys.stderr.buffer.write(result.stderr)
    return result.stdout.decode()


def exact(command, expected):
    observed = run(command)
    if observed != expected:
        raise ValueError(f"tool version mismatch: {command}: expected {expected!r}, got {observed!r}")
    print(observed.strip(), flush=True)


def inputs(lock):
    for name, accepted in ACCEPTED.items():
        source = ROOT / f"api/proto/{name}.proto"
        if digest(source) != accepted:
            raise ValueError(f"accepted schema drift: {source.relative_to(ROOT)}")
        package, alias = PACKAGES[name]
        text = source.read_text()
        expected = f"canopy.local/canopy/api/gen/{package}/v1;{alias}"
        if re.findall(r'option\s+go_package\s*=\s*"([^"]+)"\s*;', text) != [expected]:
            raise ValueError(f"Go package identity mismatch: {name}")
    for name, expected in lock["go_dependencies"]["module_files_sha256"].items():
        if digest(ROOT / name) != expected:
            raise ValueError(f"dependency drift: {name}")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=("generate", "check"))
    parser.add_argument("--go", default=os.environ.get("GO", "go"))
    parser.add_argument("--protoc", default=os.environ.get("PROTOC", "protoc"))
    args = parser.parse_args()
    lock = json.loads((ROOT / "toolchain.lock.json").read_text())
    pins = lock["tools"]
    if lock["schema_version"] != 1 or lock["module"] != "canopy.local/canopy":
        raise ValueError("unsupported toolchain lock")
    python = ".".join(map(str, sys.version_info[:3]))
    if python != pins["python"]["version"] or sys.version_info.releaselevel != "final":
        raise ValueError(f"Python version mismatch: {python}")
    inputs(lock)
    initial = {p: digest(ROOT / p) for p in ("go.mod", "go.sum", "toolchain.lock.json")}
    observed = run([args.go, "version"]).strip()
    if not re.fullmatch(r"go version go" + re.escape(pins["go"]["version"]) + r" \S+", observed):
        raise ValueError(f"Go version mismatch: {observed}")
    print(observed, flush=True)
    exact([args.protoc, "--version"], f"libprotoc {pins['protoc']['version']}\n")
    plugins = {}
    for name in ("protoc-gen-go", "protoc-gen-go-grpc"):
        pin = pins[name]
        command = [args.go, "tool", pin["package"]]
        exact(command + ["--version"], pin["expected_version_output"])
        # Resolve the same module-pinned go tool executable, never PATH plugins.
        path = run([args.go, "tool", "-n", pin["package"]]).strip()
        if not Path(path).is_file():
            raise ValueError(f"missing pinned generator: {path}")
        exact([path, "--version"], pin["expected_version_output"])
        plugins[name] = path
    with tempfile.TemporaryDirectory(prefix="canopy-proto-") as directory:
        stage = Path(directory)
        for name in ("go.mod", "go.sum"):
            (stage / name).write_bytes((ROOT / name).read_bytes())
        sources = [f"api/proto/{name}.proto" for name in ACCEPTED]
        run([args.protoc, "--proto_path=.", f"--go_out={stage}",
             "--go_opt=module=canopy.local/canopy", f"--go-grpc_out={stage}",
             "--go-grpc_opt=module=canopy.local/canopy"] +
            [f"--plugin={name}={path}" for name, path in plugins.items()] + sources)
        actual = {str(p.relative_to(stage)) for p in stage.rglob("*.go")}
        if actual != set(OUTPUTS):
            raise ValueError(f"unexpected generated output paths: {sorted(actual)}")
        # A separate compiler invocation is the schema oracle, without plugins.
        descriptor = stage / "accepted.pb"
        run([args.protoc, "--proto_path=.", f"--descriptor_set_out={descriptor}"] + sources)
        (stage / "reflect.go").write_text(REFLECT)
        print(run([args.go, "run", "-trimpath", "-buildvcs=false", "reflect.go", str(descriptor)],
                  cwd=stage), end="", flush=True)
        for name, expected in initial.items():
            if digest(ROOT / name) != expected:
                raise ValueError(f"source dependency drift during generation: {name}")
        inputs(lock)
        for name in ("go.mod", "go.sum"):
            if digest(stage / name) != initial[name]:
                raise ValueError(f"staging dependency drift: {name}")
        if args.action == "check":
            stale = [p for p in OUTPUTS if not (ROOT / p).is_file()
                     or (ROOT / p).read_bytes() != (stage / p).read_bytes()]
            if stale:
                raise ValueError("stale generated output: " + ", ".join(stale))
        else:
            for name in OUTPUTS:
                target = ROOT / name
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_bytes((stage / name).read_bytes())
        print(f"{args.action}: {len(OUTPUTS)} bindings verified offline")


if __name__ == "__main__":
    try:
        main()
    except (OSError, ValueError, KeyError, subprocess.SubprocessError) as exc:
        if isinstance(exc, subprocess.CalledProcessError):
            sys.stderr.buffer.write(exc.stdout or b"")
            sys.stderr.buffer.write(exc.stderr or b"")
        print(f"error: {exc}", file=sys.stderr)
        sys.exit(1)
