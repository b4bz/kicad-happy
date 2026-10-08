"""Offline security and release regressions; no live credentials or network."""

import importlib
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch
import urllib.error

ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / "skills" / "kicad" / "scripts"
sys.path.insert(0, str(SCRIPTS))
import digikey_auth as auth
import fab_release_gate as gate


def response(payload):
    return io.BytesIO(json.dumps(payload).encode())


class TokenSafety(unittest.TestCase):
    def setUp(self):
        importlib.reload(auth)
        self.env = patch.dict(os.environ, {
            "DIGIKEY_CLIENT_ID": "test-client", "DIGIKEY_CLIENT_SECRET": "test-secret",
        })
        self.env.start()
        self.addCleanup(self.env.stop)

    def test_memory_reuse_never_opens_disk(self):
        with patch("builtins.open", side_effect=AssertionError("disk access")), \
                patch.object(auth.urllib.request, "urlopen", return_value=response({
                    "access_token": "token-a", "expires_in": 600,
                })) as http:
            self.assertEqual(auth.get_digikey_token(), ("token-a", "test-client"))
            self.assertEqual(auth.get_digikey_token(), ("token-a", "test-client"))
            self.assertEqual(http.call_count, 1)

    def test_legacy_symlink_cache_is_ignored_and_untouched(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            target = root / "protected"
            target.write_text("do not modify")
            (root / "digikey_token_cache.json").symlink_to(target)
            with patch.dict(os.environ, {"TMPDIR": temp}), \
                    patch.object(auth.urllib.request, "urlopen", return_value=response({
                        "access_token": "new-token", "expires_in": 600,
                    })):
                self.assertEqual(auth.get_digikey_token()[0], "new-token")
            self.assertEqual(target.read_text(), "do not modify")
            self.assertEqual(len(list(root.iterdir())), 2)

    def test_both_credential_fields_invalidate(self):
        with patch.object(auth.urllib.request, "urlopen", side_effect=[
            response({"access_token": "one"}), response({"access_token": "two"}),
            response({"access_token": "three"}),
        ]) as http:
            self.assertEqual(auth.get_digikey_token()[0], "one")
            os.environ["DIGIKEY_CLIENT_SECRET"] = "rotated-secret"
            self.assertEqual(auth.get_digikey_token()[0], "two")
            os.environ["DIGIKEY_CLIENT_ID"] = "another-client"
            self.assertEqual(auth.get_digikey_token(), ("three", "another-client"))
            self.assertEqual(http.call_count, 3)

    def test_expiry_refreshes(self):
        with patch.object(auth.time, "monotonic", side_effect=[0, 539, 540]), \
                patch.object(auth.urllib.request, "urlopen", side_effect=[
                    response({"access_token": "old", "expires_in": 600}),
                    response({"access_token": "new", "expires_in": 600}),
                ]) as http:
            self.assertEqual(auth.get_digikey_token()[0], "old")
            self.assertEqual(auth.get_digikey_token()[0], "old")
            self.assertEqual(auth.get_digikey_token()[0], "new")
            self.assertEqual(http.call_count, 2)

    def test_missing_credentials_never_requests_or_reuses(self):
        with patch.object(auth.urllib.request, "urlopen", return_value=response({
            "access_token": "old",
        })) as http:
            auth.get_digikey_token()
            os.environ["DIGIKEY_CLIENT_SECRET"] = ""
            self.assertIsNone(auth.get_digikey_token())
            self.assertEqual(http.call_count, 1)

    def test_bad_responses_never_leak_to_output(self):
        for payload in [[], {}, {"access_token": 123}, {"access_token": ""},
                        {"access_token": "x", "expires_in": -1},
                        {"access_token": "x", "expires_in": "nan"}]:
            with self.subTest(payload=payload):
                importlib.reload(auth)
                with patch.object(auth.urllib.request, "urlopen", return_value=response(payload)), \
                        patch("sys.stdout", new_callable=io.StringIO) as out, \
                        patch("sys.stderr", new_callable=io.StringIO) as err:
                    self.assertIsNone(auth.get_digikey_token())
                    self.assertEqual(out.getvalue() + err.getvalue(), "")

    def test_network_failure_is_quiet_and_not_cached(self):
        with patch.object(auth.urllib.request, "urlopen", side_effect=[
            urllib.error.URLError("sensitive response"), response({"access_token": "ok"}),
        ]), patch("sys.stderr", new_callable=io.StringIO) as err:
            self.assertIsNone(auth.get_digikey_token())
            self.assertEqual(auth.get_digikey_token()[0], "ok")
            self.assertEqual(err.getvalue(), "")

    def test_all_three_consumers_use_shared_cache(self):
        sys.path.insert(0, str(ROOT / "skills" / "spice" / "scripts"))
        sys.path.insert(0, str(ROOT / "skills" / "digikey" / "scripts"))
        import lifecycle_audit
        import spice_spec_fetcher
        import fetch_datasheet_digikey
        with patch.object(auth.urllib.request, "urlopen", return_value=response({
            "access_token": "shared", "expires_in": 600,
        })) as http:
            self.assertEqual(lifecycle_audit._get_digikey_token(), ("shared", "test-client"))
            self.assertEqual(spice_spec_fetcher._get_digikey_token(), "shared")
            self.assertEqual(fetch_datasheet_digikey._get_digikey_token(), "shared")
            self.assertEqual(http.call_count, 1)


def inputs():
    """Minimal explicit evidence for the checks this gate actually consumes."""
    return {
        "sch": {"statistics": {"total_components": 2, "total_nets": 2,
                                "missing_mpn": [], "missing_footprint": []},
                "findings": []},
        "pcb": {"statistics": {"footprint_count": 2, "net_count": 2},
                "connectivity": {"total_nets_with_pads": 2, "unrouted_count": 0,
                                 "routing_complete": True},
                "dfm_summary": {"dfm_tier": "standard"}, "findings": [],
                "silkscreen": {"documentation_warnings": []}},
        "gerber_data": {"completeness": {"complete": True, "missing_required": [],
                                         "missing_recommended": []},
                        "alignment": {"aligned": True}, "findings": []},
        "thermal_data": {"summary": {"thermal_score": 100}, "findings": []},
        "emc_data": {"summary": {"emc_risk_score": 0, "by_severity": {"error": 0}},
                     "findings": []},
    }


class ReleaseSafety(unittest.TestCase):
    def test_explicit_complete_inputs_pass_with_limits(self):
        result = gate.run_gate(**inputs())
        self.assertEqual(result["overall_status"], "PASS")
        self.assertTrue(result["release_ready"])
        self.assertTrue(result["limitations"])
        self.assertNotIn("Ready for fabrication", gate.format_text_report(result))

    def test_each_missing_optional_check_blocks_pass(self):
        for name in ("gerber_data", "thermal_data", "emc_data"):
            for strict in (False, True):
                with self.subTest(name=name, strict=strict):
                    data = inputs(); data[name] = None
                    result = gate.run_gate(**data, strict=strict)
                    self.assertEqual(result["overall_status"], "INCOMPLETE")
                    self.assertFalse(result["release_ready"])

    def test_empty_or_wrong_type_input_blocks_pass(self):
        for name in inputs():
            for value in ({}, None, [], "unexpected"):
                with self.subTest(name=name, value=value):
                    data = inputs(); data[name] = value
                    self.assertEqual(gate.run_gate(**data)["overall_status"], "INCOMPLETE")

    def test_routing_defaults_and_contradictions_never_pass(self):
        for conn in ({}, {"total_nets_with_pads": 2, "routing_complete": True},
                     {"total_nets_with_pads": 2, "unrouted_count": 0, "routing_complete": False},
                     {"total_nets_with_pads": 2, "unrouted_count": 1, "routing_complete": True}):
            with self.subTest(conn=conn):
                data = inputs(); data["pcb"]["connectivity"] = conn
                self.assertNotEqual(gate.run_gate(**data)["overall_status"], "PASS")

    def test_current_gerber_schema_missing_layers_fails(self):
        for field in ("missing_required", "missing", "missing_layers"):
            data = inputs(); data["gerber_data"]["completeness"] = {
                "complete": False, field: ["F.Cu"],
            }
            self.assertEqual(gate.run_gate(**data)["overall_status"], "FAIL")

    def test_missing_alignment_and_drills_do_not_default_to_success(self):
        data = inputs(); del data["gerber_data"]["alignment"]
        self.assertEqual(gate.run_gate(**data)["overall_status"], "INCOMPLETE")
        data = inputs(); data["gerber_data"]["completeness"]["complete"] = False
        self.assertEqual(gate.run_gate(**data)["overall_status"], "FAIL")

    def test_unknown_dfm_with_metrics_does_not_pass(self):
        data = inputs(); data["pcb"]["dfm_summary"] = {"dfm_tier": "unknown", "metrics": {"width": 1}}
        self.assertEqual(gate.run_gate(**data)["overall_status"], "INCOMPLETE")

    def test_unknown_finding_severity_blocks_pass(self):
        for severity in (None, "mystery", 123):
            data = inputs(); data["pcb"]["findings"] = [{"severity": severity}]
            self.assertEqual(gate.run_gate(**data)["overall_status"], "INCOMPLETE")

    def test_analyzer_errors_fail_even_when_aggregate_checks_pass(self):
        for name in ("sch", "pcb", "gerber_data", "thermal_data"):
            with self.subTest(name=name):
                data = inputs(); data[name]["findings"] = [{"severity": "error", "components": ["U1"]}]
                self.assertEqual(gate.run_gate(**data)["overall_status"], "FAIL")

    def test_current_emc_severity_schema_never_silently_passes(self):
        data = inputs(); data["emc_data"]["summary"]["by_severity"]["error"] = 1
        data["emc_data"]["findings"] = [{"severity": "error"}]
        self.assertEqual(gate.run_gate(**data)["overall_status"], "WARN")
        self.assertEqual(gate.run_gate(**data, strict=True)["overall_status"], "FAIL")

    def test_known_error_overrides_incomplete(self):
        data = inputs(); data["gerber_data"] = None
        data["pcb"]["connectivity"]["unrouted_count"] = 1
        self.assertEqual(gate.run_gate(**data)["overall_status"], "FAIL")

    def test_skipped_analysis_and_trust_blockers_block_pass(self):
        data = inputs(); data["thermal_data"]["summary"]["skipped_reason"] = "missing specs"
        self.assertEqual(gate.run_gate(**data)["overall_status"], "INCOMPLETE")
        data = inputs(); data["sch"]["trust_summary"] = {"unknown_confidence": 1}
        self.assertEqual(gate.run_gate(**data)["overall_status"], "INCOMPLETE")

    def cli(self, data, **options):
        with tempfile.TemporaryDirectory() as temp:
            cmd = [sys.executable, str(SCRIPTS / "fab_release_gate.py")]
            for name, flag in (("sch", "--schematic"), ("pcb", "--pcb"),
                               ("gerber_data", "--gerbers"), ("thermal_data", "--thermal"),
                               ("emc_data", "--emc")):
                if data[name] is None:
                    continue
                p = Path(temp) / (name + ".json"); p.write_text(json.dumps(data[name]))
                cmd += [flag, str(p)]
            cmd += options.get("extra", [])
            return subprocess.run(cmd, capture_output=True, text=True, timeout=15)

    def test_cli_exit_codes_follow_verdict(self):
        for status, code in (("PASS", 0), ("FAIL", 1), ("INCOMPLETE", 2), ("WARN", 3)):
            with self.subTest(status=status):
                data = inputs()
                if status == "FAIL": data["pcb"]["connectivity"]["unrouted_count"] = 1
                if status == "INCOMPLETE": data["gerber_data"] = None
                if status == "WARN": data["pcb"]["findings"] = [{"severity": "warning"}]
                result = self.cli(data)
                self.assertEqual(result.returncode, code, result.stderr)
                self.assertEqual(json.loads(result.stdout)["overall_status"], status)

    def test_cli_malformed_json_and_missing_explicit_file_fail(self):
        with tempfile.TemporaryDirectory() as temp:
            bad = Path(temp) / "bad.json"; bad.write_text("{")
            for path in (bad, Path(temp) / "missing.json"):
                result = subprocess.run([sys.executable, str(SCRIPTS / "fab_release_gate.py"),
                                         "-s", str(path), "-p", str(path)],
                                        capture_output=True, text=True, timeout=15)
                self.assertEqual(result.returncode, 2)


if __name__ == "__main__":
    unittest.main()
