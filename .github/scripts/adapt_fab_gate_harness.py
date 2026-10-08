#!/usr/bin/env python3
"""Update exactly two legacy smoke assertions to the hardened exit contract.

Applied only to a temporary upstream harness checkout, never to design data.
These tests used to require success for missing fabrication inputs. Keep them
running, require INCOMPLETE with exit 2, and fail if their source has changed.
"""

import argparse
from pathlib import Path


def adapt(harness):
    path = Path(harness) / "tests" / "test_downstream_tools.py"
    source = path.read_text()
    old = '        assert r.returncode == 0, f"Crash: {r.stderr[:300]}"'
    new = ('        assert r.returncode == 2, f"Expected blocked incomplete gate: {r.stderr[:300]}"\n'
           '        result = json.loads(r.stdout)\n'
           '        assert result["overall_status"] == "INCOMPLETE"\n'
           '        assert result["release_ready"] is False')
    for name in ("test_fab_gate_no_crash", "test_fab_gate_backward_compat"):
        start = source.index("def " + name + "():")
        end = source.find("\ndef ", start + 1)
        if end == -1:
            end = len(source)
        block = source[start:end]
        if block.count(old) != 1:
            raise ValueError(f"Unexpected upstream test contract: {name}; review before adapting")
        source = source[:start] + block.replace(old, new) + source[end:]
    path.write_text(source)
    print("Updated two legacy fabrication-gate exit assertions; all tests remain enabled.")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("harness", help="Temporary upstream harness checkout")
    adapt(parser.parse_args().harness)
