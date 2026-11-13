#!/usr/bin/env python3
"""Fresh local v1 vector verification; not recovery of historical approvals.

Run from any directory: python3 tests/conformance/oracle.py
Only Python's standard library is used. No product code is imported or invoked.
The contract remains a candidate; verification does not ratify or accept it.
"""

import argparse
import hashlib
import json
from pathlib import Path
import re
import struct
import sys

ROOT = Path(__file__).resolve().parents[2]
HISTORICAL = (
    "accepted_literal_source", "independent_vector_receipt",
    "independent_generator", "independent_vector_run",
)


def require(condition, message):
    if not condition:
        raise ValueError(message)


def raw(value):
    require(isinstance(value, str) and re.fullmatch(r"(?:[0-9a-f]{2})*", value),
            "expected canonical lowercase byte hex")
    return bytes.fromhex(value)


def field(value, limit):
    data = raw(value)
    require(len(data) <= limit, "field length exceeds canonical limit")
    return struct.pack(">I", len(data)) + data


def tid(value, kind):
    data = raw(value)
    require(len(data) == 35 and data[:3] == struct.pack(">HB", 1, kind),
            "invalid embedded typed ID")
    return data


def metadata(value):
    require(-1439 <= value["offset"] <= 1439, "invalid timezone offset")
    return field(value["identity_hex"], 65536) + struct.pack(
        ">qh", value["seconds"], value["offset"])


def optional(value, encode):
    return b"\x00" if value is None else b"\x01" + encode(value)


def frame(vector):
    kind = vector["kind"]
    require(kind in (1, 2), "unknown canonical kind")
    if kind == 1:
        payload = raw(vector["blob_hex"])
        require(len(payload) <= 1 << 40, "blob limit exceeded")
    else:
        value = vector["input"]
        repo = raw(value["repo_hex"])
        require(len(repo) == 16, "repository ID must be 16 bytes")
        parents = value["parents"]
        require(len(parents) <= 1024, "parent limit exceeded")
        payload = repo + struct.pack(">I", len(parents))
        payload += b"".join(tid(parent, 2) for parent in parents)
        payload += metadata(value["author"])
        payload += optional(value["committer"], metadata)
        payload += field(value["message_hex"], 16 << 20)
        payload += optional(value["encoding_hex"], lambda x: field(x, 256))
        operations = value["operations"]
        require(len(operations) <= 1000000, "operation limit exceeded")
        payload += struct.pack(">I", len(operations))
        previous = None
        set_paths = set()
        for op in operations:
            path = raw(op["path_hex"])
            parts = path.split(b"/")
            require(0 < len(path) <= 65535 and b"\x00" not in path
                    and len(parts) <= 1024
                    and all(p not in (b"", b".", b"..") for p in parts),
                    "invalid canonical path")
            require(previous is None or previous < path, "paths not strictly ordered")
            previous = path
            tag = op["tag"]
            require(tag in (0, 1, 2, 3), "unknown operation tag")
            require(op["mode"] == (0, 0o100644, 0o100755, 0o120000)[tag],
                    "fixture mode disagrees with operation tag")
            payload += field(op["path_hex"], 65535) + struct.pack(">B", tag)
            if tag == 0:
                require(op["target_hex"] is None, "DELETE has target")
            else:
                payload += tid(op["target_hex"], 1)
                # Only SET ancestors conflict, even with other intervening paths.
                require(not any(b"/".join(parts[:i]) in set_paths
                                for i in range(1, len(parts))), "conflicting SET paths")
                set_paths.add(path)
        require(len(payload) <= 64 << 20, "changeset limit exceeded")
    return b"CANOPY\x00OBJ\x00" + struct.pack(">HBQ", 1, kind, len(payload)) + payload


def seeded_input(seed, literals):
    """Current explicit recipe, reproduced from the checked-in primitive fixtures.

    LCG32: state=(1664525*state+1013904223) mod 2^32; emit high byte.
    Emit repo16, author7, message11 in that order. No historical origin claimed.
    """
    state = seed

    def generate(count):
        nonlocal state
        result = bytearray()
        for _ in range(count):
            state = (1664525 * state + 1013904223) & 0xffffffff
            result.append(state >> 24)
        return result.hex()

    a = literals["root_A_message_ff"]["typed_id"]
    b = literals["nonutf8_ff_executable_parent_A"]["typed_id"]
    blob = literals["blob_x"]["typed_id"]
    value = {
        "repo_hex": generate(16),
        "parents": [b, a, b] if seed & 1 else [a, b, a],
        "author": {"identity_hex": generate(7), "seconds": -1700000000 - seed,
                   "offset": -1439 + seed % 2879},
        "committer": {"identity_hex": "", "seconds": 0, "offset": 0} if seed & 1 else None,
        "message_hex": generate(11),
        "encoding_hex": "" if seed & 2 else None,
        "operations": [],
    }
    for path, tag in zip(("41", "61", "65cc81", "7a2fff", "c3a9", "ff"), (1, 2, 3, 0, 1, 2)):
        value["operations"].append({
            "path_hex": path, "tag": tag, "target_hex": blob if tag else None,
            "mode": (0, 0o100644, 0o100755, 0o120000)[tag],
        })
    return value


def verify(fixtures_path, contract_path):
    fixtures = json.loads(fixtures_path.read_text())
    require(fixtures["schema_version"] == 1, "unsupported fixture schema")
    provenance = fixtures["provenance"]
    for name in HISTORICAL:
        record = provenance[name]
        require(record["status"] == "unavailable-unverified", "historical status missing")
        require(record["path"].startswith("/Users/completetech/github/.scion-run/evidence/"),
                "historical evidence path missing")
        require(re.fullmatch(r"[0-9a-f]{64}", record["sha256"]), "historical digest missing")
    fresh = provenance["local_reproducibility"]
    for key, path in (("contract", contract_path), ("oracle", Path(__file__).resolve())):
        require(hashlib.sha256(path.read_bytes()).hexdigest() == fresh[key]["sha256"],
                key + " source hash differs from recorded local reproducibility source")
    text = contract_path.read_text()
    rows = re.findall(r"\| (\w+) \| `([0-9a-f]+)` \| `([0-9a-f]{64})` \|", text)
    contract = {name: (preimage, digest) for name, preimage, digest in rows}
    require(len(rows) == len(contract) == 19, "expected exactly 19 unique contract vectors")
    literals, seeded = fixtures["accepted_literals"], fixtures["seeded_cases"]
    require(len(literals) == 19 and len(seeded) == 4, "fixture inventory differs")
    by_name = {v["name"]: v for v in literals}
    require(set(by_name) == set(contract), "literal names differ from contract table")
    require({v["seed"] for v in seeded} == set(range(0xd0100000, 0xd0100004)),
            "seed inventory differs")
    seen = set()
    for vector in literals + seeded:
        name = vector["name"]
        require(name and name not in seen, "duplicate or empty vector name")
        seen.add(name)
        if name in by_name:
            require((vector["preimage"], vector["digest"]) == contract[name],
                    name + ": fixture differs from published contract table")
        else:
            seed = vector["seed"]
            require(vector["seed_hex"] == f"{seed:08x}" and vector["kind"] == 2,
                    name + ": invalid seed metadata")
            require(vector["input"] == seeded_input(seed, by_name), name + ": seed recipe differs")
        encoded = frame(vector)
        digest = hashlib.sha256(encoded).hexdigest()
        require(encoded.hex() == vector["preimage"], name + ": preimage mismatch")
        require(digest == vector["digest"], name + ": digest mismatch")
        require(vector["typed_id"] == struct.pack(">HB", 1, vector["kind"]).hex() + digest,
                name + ": typed ID mismatch")
        print(f"PASS {name} seed={vector.get('seed_hex', '-')} bytes={len(encoded)} sha256={digest}")
    print("PASS 19 contract literals + 4 seeded vectors; fresh local verification only")
    print("Historical provenance: four records remain unavailable/unverified; no approvals recovered")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--fixtures", type=Path, default=ROOT / "tests/conformance/testdata/canonical_v1.json")
    parser.add_argument("--contract", type=Path, default=ROOT / "api/contracts/canonical.md")
    args = parser.parse_args()
    try:
        verify(args.fixtures, args.contract)
    except (ValueError, KeyError, TypeError, OSError, struct.error) as error:
        print(f"FAIL {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
