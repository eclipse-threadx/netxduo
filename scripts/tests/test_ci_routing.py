#!/usr/bin/env python3
##############################################################################
# Copyright (c) 2026 Eclipse ThreadX contributors
#
# This program and the accompanying materials are made available under the
# terms of the MIT License which is available at
# https://opensource.org/licenses/MIT.
#
# SPDX-License-Identifier: MIT
##############################################################################

"""Regression tests for conditional dev CI routing and gate aggregation."""

import copy
import io
import json
import runpy
import subprocess
import sys
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
from unittest import mock


SCRIPTS_DIRECTORY = Path(__file__).resolve().parents[1]
CI_DIRECTORY = SCRIPTS_DIRECTORY / "ci"
sys.path.insert(0, str(CI_DIRECTORY))

import check_dev_gate  # noqa: E402
import classify_changes  # noqa: E402


class ClassifierTests(unittest.TestCase):
    """Verify path routing, profile-map integrity, and conservative fallbacks."""

    @classmethod
    def setUpClass(cls):
        """Load the checked-in map once for classifier tests."""
        cls.profile_map = classify_changes.load_profile_map(
            CI_DIRECTORY / "profile_map.json"
        )

    def classify(self, *paths, forced_reason=None):
        """Classify a short path list with the checked-in map."""
        return classify_changes.classify_files(
            paths, self.profile_map, forced_reason=forced_reason
        )

    @staticmethod
    def netxduo_profiles(outputs):
        """Flatten NetX Duo matrix profiles from classifier outputs."""
        return {
            profile
            for entry in json.loads(outputs["netxduo_matrix"])
            for profile in entry["profiles"].split()
        }

    @staticmethod
    def secure_interoperability_profiles(outputs):
        """Flatten secure interoperability profiles from classifier outputs."""
        return {
            profile
            for entry in json.loads(outputs["nx_secure_interoperability_matrix"])
            for profile in entry["profiles"].split()
        }

    def test_profile_map_matches_every_cmake_suite(self):
        """The map and checked-in shard partitions cover profiles exactly."""
        classify_changes.validate_profile_map(self.profile_map)
        expected_counts = {
            "netxduo": 43,
            "web": 3,
            "ptp": 3,
            "mqtt": 9,
            "mqtt_interoperability": 9,
            "netxduo64": 1,
            "netxduo_fast": 1,
            "nx_secure": 19,
            "nx_secure_interoperability": 18,
            "crypto": 4,
        }
        self.assertEqual(
            expected_counts,
            {
                suite: len(configuration["profiles"])
                for suite, configuration in self.profile_map["suites"].items()
            },
        )

    def test_empty_and_docs_only_changes_run_real_smoke_only(self):
        """Documentation and sample changes add nothing beyond mandatory smoke."""
        for paths in ((), ("docs/networking.md",), ("samples/demo/sample.c",)):
            with self.subTest(paths=paths):
                outputs = self.classify(*paths)
                self.assertEqual("false", outputs["full"])
                self.assertEqual("[]", outputs["netxduo_matrix"])
                self.assertEqual(
                    "[]", outputs["nx_secure_interoperability_matrix"]
                )
                for output_name in classify_changes.SUITE_OUTPUTS.values():
                    self.assertEqual("", outputs[output_name])

    def test_public_header_selects_every_profile_once(self):
        """A public header produces full routing without duplicating smoke."""
        outputs = self.classify("common/inc/nx_api.h")
        self.assertEqual("true", outputs["full"])
        matrix = json.loads(outputs["netxduo_matrix"])
        self.assertEqual(8, len(matrix))
        expected = set(self.profile_map["suites"]["netxduo"]["profiles"])
        expected.remove("default_build_coverage")
        self.assertEqual(expected, self.netxduo_profiles(outputs))
        secure_matrix = json.loads(
            outputs["nx_secure_interoperability_matrix"]
        )
        self.assertEqual(6, len(secure_matrix))
        self.assertEqual(
            set(
                self.profile_map["suites"]["nx_secure_interoperability"][
                    "profiles"
                ]
            ),
            self.secure_interoperability_profiles(outputs),
        )
        for output_name in classify_changes.SUITE_OUTPUTS.values():
            self.assertEqual("all", outputs[output_name])

    def test_secure_interoperability_matrix_filters_partial_shards(self):
        """Only selected secure profiles and non-empty shards enter the matrix."""
        selection = classify_changes.Selection(self.profile_map)
        selection.selected["nx_secure_interoperability"].update(
            {
                "default_build_coverage",
                "tls_1_3_enable_build_coverage",
                "curve25519_448_build",
            }
        )
        outputs = selection.outputs(1)
        matrix = json.loads(outputs["nx_secure_interoperability_matrix"])
        self.assertEqual(
            ["baseline", "tls13"], [entry["name"] for entry in matrix]
        )
        self.assertEqual(
            {
                "default_build_coverage",
                "tls_1_3_enable_build_coverage",
                "curve25519_448_build",
            },
            self.secure_interoperability_profiles(outputs),
        )
        self.assertEqual(
            "Dev-Secure-Interoperability-tls13", matrix[1]["result_name"]
        )

    def test_ipv4_source_selects_ipv4_and_dependent_defaults(self):
        """IPv4 implementation changes cover all IPv4 variants and consumers."""
        outputs = self.classify("common/src/nx_arp_enable.c")
        selected = self.netxduo_profiles(outputs)
        expected = {
            profile
            for profile in self.profile_map["suites"]["netxduo"]["profiles"]
            if profile.startswith("v4_")
        }
        self.assertEqual(expected, selected)
        self.assertEqual("default_build_coverage", outputs["web_profiles"])
        self.assertEqual("default_build_coverage", outputs["netxduo64_profiles"])
        self.assertEqual("v6_full_build", outputs["netxduo_fast_profiles"])

    def test_ipv6_source_selects_ipv6_and_dependent_defaults(self):
        """IPv6 implementation changes cover all IPv6 variants and consumers."""
        for source in ("nx_ipv6_packet_send.c", "nx_icmp_interface_ping6.c"):
            with self.subTest(source=source):
                outputs = self.classify("common/src/" + source)
                selected = self.netxduo_profiles(outputs)
                expected = {
                    profile
                    for profile in self.profile_map["suites"]["netxduo"]["profiles"]
                    if profile.startswith("v6_")
                }
                self.assertEqual(expected, selected)
                self.assertEqual(
                    "default_build_coverage", outputs["nx_secure_profiles"]
                )

    def test_shared_source_selects_representatives_and_consumers(self):
        """Shared TCP/UDP/IP/packet code covers both stacks, 64-bit, and fast."""
        outputs = self.classify("common/src/nx_tcp_socket_send.c")
        self.assertEqual(
            {"v4_build", "v4_full_build", "v6_build", "v6_full_build"},
            self.netxduo_profiles(outputs),
        )
        self.assertEqual("default_build_coverage", outputs["netxduo64_profiles"])
        self.assertEqual("v6_full_build", outputs["netxduo_fast_profiles"])
        self.assertEqual("default_build_coverage", outputs["mqtt_profiles"])

    def test_mqtt_and_cloud_changes_select_both_mqtt_families(self):
        """MQTT sources and cloud consumers route to regular and interop suites."""
        for path in ("addons/mqtt/nxd_mqtt_client.c", "addons/cloud/nx_cloud.c"):
            with self.subTest(path=path):
                outputs = self.classify(path)
                self.assertEqual("all", outputs["mqtt_profiles"])
                self.assertEqual("all", outputs["mqtt_interoperability_profiles"])

    def test_websocket_change_selects_secure_mqtt_and_netxduo_profiles(self):
        """WebSocket changes cover their MQTT and NetX Duo consumers."""
        outputs = self.classify("addons/websocket/nx_websocket_client.c")
        self.assertEqual(
            "websocket_secure_build", outputs["mqtt_profiles"]
        )
        self.assertEqual(
            "websocket_secure_build", outputs["mqtt_interoperability_profiles"]
        )
        self.assertEqual(
            {"v4_build", "v6_full_secure_build"}, self.netxduo_profiles(outputs)
        )

    def test_web_http_and_ptp_tsn_routes(self):
        """Web, HTTP, PTP, and TSN changes select their dedicated suites."""
        web = self.classify("addons/http/nx_http_server.c")
        self.assertEqual("all", web["web_profiles"])
        self.assertEqual(
            {"v4_build", "v6_build", "v6_full_secure_build"},
            self.netxduo_profiles(web),
        )
        for path in ("addons/ptp/nx_ptp_client.c", "tsn/src/nx_shaper.c"):
            with self.subTest(path=path):
                ptp = self.classify(path)
                self.assertEqual("all", ptp["ptp_profiles"])
                self.assertEqual(
                    {"tsn_build_coverage"}, self.netxduo_profiles(ptp)
                )

    def test_secure_change_selects_security_consumers(self):
        """NetX Secure changes cover TLS, Web, MQTT, and secure NetX Duo."""
        outputs = self.classify("nx_secure/src/nx_secure_tls_session_create.c")
        self.assertEqual("all", outputs["nx_secure_profiles"])
        self.assertEqual("all", outputs["nx_secure_interoperability_profiles"])
        self.assertEqual(
            6, len(json.loads(outputs["nx_secure_interoperability_matrix"]))
        )
        self.assertEqual("all", outputs["web_profiles"])
        self.assertIn("secure_build_coverage", outputs["mqtt_profiles"].split())
        self.assertEqual(
            {"v6_full_secure_build"}, self.netxduo_profiles(outputs)
        )
        self.assertEqual("", outputs["crypto_profiles"])

    def test_crypto_change_adds_crypto_suite(self):
        """Cryptography changes add all crypto profiles to security consumers."""
        outputs = self.classify("crypto_libraries/src/nx_crypto_aes.c")
        self.assertEqual("all", outputs["crypto_profiles"])
        self.assertEqual("all", outputs["nx_secure_profiles"])
        self.assertEqual("all", outputs["nx_secure_interoperability_profiles"])

    def test_generic_addon_and_utility_select_netxduo_representatives(self):
        """Known network add-ons and utilities select core and fast coverage."""
        for path in ("addons/dns/nx_dns.c", "utility/iperf/nx_iperf.c"):
            with self.subTest(path=path):
                outputs = self.classify(path)
                self.assertEqual(
                    {"v4_build", "v6_build"}, self.netxduo_profiles(outputs)
                )
                self.assertEqual("v6_full_build", outputs["netxduo_fast_profiles"])

    def test_regression_components_route_to_every_compiling_suite(self):
        """Regression paths select all profiles in the suites that compile them."""
        cases = {
            "test/regression/netxduo_test/netx_test.c": {
                "netxduo64_profiles": "all",
                "netxduo_fast_profiles": "all",
            },
            "test/regression/bsd_test/netx_bsd_test.c": {
                "netxduo_fast_profiles": "all"
            },
            "test/regression/ptp_test/netx_ptp_test.c": {
                "ptp_profiles": "all",
                "netxduo_fast_profiles": "all",
            },
            "test/regression/mqtt_test/netx_mqtt_test.c": {
                "mqtt_profiles": "all"
            },
            "test/regression/web_test/netx_web_test.c": {"web_profiles": "all"},
            "test/regression/nx_secure_test/nx_secure_test.c": {
                "nx_secure_profiles": "all",
                "crypto_profiles": "all",
            },
            "test/regression/interoperability_test/mqtt_test/test.c": {
                "mqtt_interoperability_profiles": "all"
            },
            "test/regression/interoperability_test/nx_secure_test/test.c": {
                "nx_secure_interoperability_profiles": "all"
            },
            "test/regression/interoperability_test/test_frame/test.c": {
                "mqtt_interoperability_profiles": "all",
                "nx_secure_interoperability_profiles": "all",
            },
        }
        for path, expected_outputs in cases.items():
            with self.subTest(path=path):
                outputs = self.classify(path)
                for output_name, value in expected_outputs.items():
                    self.assertEqual(value, outputs[output_name])

    def test_suite_cmake_change_selects_that_entire_suite(self):
        """A suite-local CMake change selects all profiles only in that suite."""
        outputs = self.classify("test/cmake/web/CMakeLists.txt")
        self.assertEqual("all", outputs["web_profiles"])
        self.assertEqual("[]", outputs["netxduo_matrix"])
        self.assertEqual("", outputs["mqtt_profiles"])

    def test_shared_suite_cmake_changes_select_consumers(self):
        """Included and symlinked suite inputs route to every consuming suite."""
        netxduo = self.classify("test/cmake/netxduo/CMakeLists.txt")
        self.assertEqual("all", netxduo["netxduo64_profiles"])
        self.assertEqual("all", netxduo["netxduo_fast_profiles"])
        self.assertEqual("all", netxduo["ptp_profiles"])
        mqtt = self.classify("test/cmake/mqtt/CMakeLists.txt")
        self.assertEqual("all", mqtt["mqtt_profiles"])
        self.assertEqual("all", mqtt["mqtt_interoperability_profiles"])
        secure = self.classify("test/cmake/nx_secure/CMakeLists.txt")
        self.assertEqual("all", secure["nx_secure_profiles"])
        self.assertEqual("all", secure["nx_secure_interoperability_profiles"])

    def test_broad_unknown_and_malformed_paths_fall_back_to_full(self):
        """Shared infrastructure, unknown paths, and malformed paths run all."""
        paths = (
            "CMakeLists.txt",
            ".github/workflows/ci-dev.yml",
            "scripts/install.sh",
            ".gitmodules",
            "test/cmake/threadx/scripts/cmake_bootstrap.sh",
            "addons/azure_iot/nx_azure_iot.c",
            "unknown/new.file",
            "../outside",
            "bad\\path",
            "",
        )
        for path in paths:
            with self.subTest(path=path):
                self.assertEqual("true", self.classify(path)["full"])

    def test_unknown_regression_paths_fall_back_to_full(self):
        """Broad or unknown regression paths cannot silently reduce coverage."""
        paths = (
            "test/regression/readme.txt",
            "test/regression/unknown_test/test.c",
            "test/regression/interoperability_test/unknown/test.c",
            "test/regression/test/netxtestcontrol.c",
        )
        for path in paths:
            with self.subTest(path=path):
                self.assertEqual("true", self.classify(path)["full"])

        for path in (
            "test/regression",
            "test/regression/interoperability_test",
        ):
            with self.subTest(direct_path=path):
                selection = classify_changes.Selection(self.profile_map)
                classify_changes._classify_regression_path(path, selection)
                self.assertEqual("true", selection.outputs(1)["full"])

    def test_multiple_component_changes_union_profiles(self):
        """Independent component routes are merged deterministically."""
        outputs = self.classify(
            "addons/mqtt/nxd_mqtt_client.c", "addons/ptp/nx_ptp_client.c"
        )
        self.assertEqual("all", outputs["mqtt_profiles"])
        self.assertEqual("all", outputs["mqtt_interoperability_profiles"])
        self.assertEqual("all", outputs["ptp_profiles"])
        self.assertEqual(
            {"tsn_build_coverage"}, self.netxduo_profiles(outputs)
        )

    def test_forced_and_unreliable_ranges_fall_back_to_full(self):
        """Manual runs and unresolvable Git ranges select every suite."""
        forced = self.classify(forced_reason="manual dispatch")
        self.assertEqual("true", forced["full"])
        self.assertEqual(
            None, classify_changes.changed_files_from_git("missing", "also-missing")
        )
        self.assertEqual(None, classify_changes.changed_files_from_git("0" * 40, "HEAD"))
        self.assertEqual(
            None,
            classify_changes.changed_files_from_git("1" * 40, "2" * 40),
        )
        base_revision = subprocess.run(
            ["git", "rev-parse", "HEAD~1"],
            check=True,
            stdout=subprocess.PIPE,
            text=True,
        ).stdout.strip()
        head_revision = subprocess.run(
            ["git", "rev-parse", "HEAD"],
            check=True,
            stdout=subprocess.PIPE,
            text=True,
        ).stdout.strip()
        changed_paths = classify_changes.changed_files_from_git(
            base_revision, head_revision
        )
        self.assertIsInstance(changed_paths, list)
        self.assertTrue(changed_paths)

    def test_outputs_and_summary_are_written_for_github(self):
        """GitHub output and summary files contain stable routing information."""
        outputs = self.classify("addons/mqtt/nxd_mqtt_client.c")
        with tempfile.TemporaryDirectory() as temporary_directory:
            output_file = Path(temporary_directory) / "output"
            summary_file = Path(temporary_directory) / "summary"
            classify_changes.write_github_outputs(output_file, outputs)
            classify_changes.write_summary(
                summary_file, outputs, ["addons/mqtt/nxd_mqtt_client.c"]
            )
            output_text = output_file.read_text(encoding="utf-8")
            summary_text = summary_file.read_text(encoding="utf-8")
        self.assertIn("mqtt_profiles=all\n", output_text)
        self.assertIn("## Dev CI routing", summary_text)
        self.assertIn("addons/mqtt/nxd_mqtt_client.c", summary_text)

        many_paths = [f"docs/path-{index}.md" for index in range(51)]
        with tempfile.TemporaryDirectory() as temporary_directory:
            summary_file = Path(temporary_directory) / "summary"
            classify_changes.write_summary(summary_file, outputs, many_paths)
            summary_text = summary_file.read_text(encoding="utf-8")
        self.assertIn("... and 1 more", summary_text)

        with tempfile.TemporaryDirectory() as temporary_directory:
            summary_file = Path(temporary_directory) / "summary"
            classify_changes.write_summary(summary_file, outputs, ["docs/a\nb`c"])
            summary_text = summary_file.read_text(encoding="utf-8")
        self.assertIn("docs/a?b'c", summary_text)

    def test_static_error_fallback_matches_full_classifier_output(self):
        """The shell-safe error fallback remains identical to full routing."""
        fallback = {}
        fallback_file = CI_DIRECTORY / "full_fallback_outputs"
        for line in fallback_file.read_text(encoding="utf-8").splitlines():
            name, value = line.split("=", 1)
            fallback[name] = value
        expected = self.classify(forced_reason="classifier error")
        self.assertEqual(expected, fallback)

    def test_invalid_profile_maps_are_rejected(self):
        """Stale profiles, shards, bundles, and schema versions fail validation."""
        mutations = []
        invalid_version = copy.deepcopy(self.profile_map)
        invalid_version["version"] = 2
        mutations.append(invalid_version)
        invalid_structure = {"version": 1, "suites": [], "bundles": {}}
        mutations.append(invalid_structure)
        missing_suite = copy.deepcopy(self.profile_map)
        del missing_suite["suites"]["web"]
        mutations.append(missing_suite)
        duplicate_profile = copy.deepcopy(self.profile_map)
        duplicate_profile["suites"]["web"]["profiles"].append(
            "default_build_coverage"
        )
        mutations.append(duplicate_profile)
        missing_shard_profile = copy.deepcopy(self.profile_map)
        missing_shard_profile["suites"]["netxduo"]["shards"][0]["profiles"].pop()
        mutations.append(missing_shard_profile)
        stale_suite = copy.deepcopy(self.profile_map)
        stale_suite["suites"]["web"]["profiles"][0] = "stale_build"
        mutations.append(stale_suite)
        invalid_smoke = copy.deepcopy(self.profile_map)
        invalid_smoke["suites"]["netxduo"]["smoke"] = "missing_build"
        mutations.append(invalid_smoke)
        duplicate_shard_profile = copy.deepcopy(self.profile_map)
        duplicate_shard_profile["suites"]["netxduo"]["shards"][1][
            "profiles"
        ].append("v4_build")
        mutations.append(duplicate_shard_profile)
        duplicate_shard_name = copy.deepcopy(self.profile_map)
        duplicate_shard_name["suites"]["netxduo"]["shards"][1]["name"] = (
            "shard-1"
        )
        mutations.append(duplicate_shard_name)
        missing_secure_shard_profile = copy.deepcopy(self.profile_map)
        missing_secure_shard_profile["suites"]["nx_secure_interoperability"][
            "shards"
        ][1]["profiles"].pop()
        mutations.append(missing_secure_shard_profile)
        duplicate_secure_shard_profile = copy.deepcopy(self.profile_map)
        duplicate_secure_shard_profile["suites"]["nx_secure_interoperability"][
            "shards"
        ][1]["profiles"].append("default_build_coverage")
        mutations.append(duplicate_secure_shard_profile)
        duplicate_secure_shard_name = copy.deepcopy(self.profile_map)
        duplicate_secure_shard_name["suites"]["nx_secure_interoperability"][
            "shards"
        ][1]["name"] = "baseline"
        mutations.append(duplicate_secure_shard_name)
        empty_secure_shard = copy.deepcopy(self.profile_map)
        empty_secure_shard["suites"]["nx_secure_interoperability"]["shards"][
            0
        ]["profiles"] = []
        mutations.append(empty_secure_shard)
        missing_secure_shards = copy.deepcopy(self.profile_map)
        del missing_secure_shards["suites"]["nx_secure_interoperability"][
            "shards"
        ]
        mutations.append(missing_secure_shards)
        empty_bundle = copy.deepcopy(self.profile_map)
        empty_bundle["bundles"]["netx_addon"] = {}
        mutations.append(empty_bundle)
        unknown_bundle_suite = copy.deepcopy(self.profile_map)
        unknown_bundle_suite["bundles"]["netx_addon"]["unknown"] = "all"
        mutations.append(unknown_bundle_suite)
        invalid_bundle_profiles = copy.deepcopy(self.profile_map)
        invalid_bundle_profiles["bundles"]["netx_addon"]["web"] = []
        mutations.append(invalid_bundle_profiles)
        unknown_bundle_profile = copy.deepcopy(self.profile_map)
        unknown_bundle_profile["bundles"]["netx_addon"]["web"] = ["missing"]
        mutations.append(unknown_bundle_profile)
        for profile_map in mutations:
            with self.subTest(version=profile_map.get("version")):
                with self.assertRaises(classify_changes.ProfileMapError):
                    classify_changes.validate_profile_map(profile_map)

        with tempfile.TemporaryDirectory() as temporary_directory:
            cmake_file = Path(temporary_directory) / "CMakeLists.txt"
            cmake_file.write_text("project(no_profiles)\n", encoding="utf-8")
            with self.assertRaises(classify_changes.ProfileMapError):
                classify_changes.parse_cmake_profiles(cmake_file)

        selection = classify_changes.Selection(self.profile_map)
        selection.selected["netxduo"].add("not_sharded_build")
        with self.assertRaises(classify_changes.ProfileMapError):
            selection.outputs(1)

        selection = classify_changes.Selection(self.profile_map)
        selection.selected["nx_secure_interoperability"].add(
            "not_sharded_build"
        )
        with self.assertRaises(classify_changes.ProfileMapError):
            selection.outputs(1)

    def test_command_line_validation_and_files_input(self):
        """The classifier CLI validates maps and emits local JSON selections."""
        stdout = io.StringIO()
        with redirect_stdout(stdout):
            self.assertEqual(0, classify_changes.main(["--validate"]))
        self.assertIn("validation passed", stdout.getvalue())

        with tempfile.TemporaryDirectory() as temporary_directory:
            paths_file = Path(temporary_directory) / "paths"
            paths_file.write_text("docs/readme.md\n", encoding="utf-8")
            stdout = io.StringIO()
            with redirect_stdout(stdout):
                result = classify_changes.main(
                    ["--files-from", str(paths_file)]
                )
        self.assertEqual(0, result)
        self.assertEqual("false", json.loads(stdout.getvalue())["full"])

    def test_command_line_fallback_and_github_files(self):
        """CLI failures become full selections and GitHub files are populated."""
        with tempfile.TemporaryDirectory() as temporary_directory:
            temporary_path = Path(temporary_directory)
            invalid_map = temporary_path / "invalid.json"
            invalid_map.write_text("{}", encoding="utf-8")
            stderr = io.StringIO()
            with redirect_stderr(stderr):
                self.assertEqual(
                    2, classify_changes.main(["--map", str(invalid_map)])
                )
            self.assertIn("validation failed", stderr.getvalue())

            malformed_map = temporary_path / "malformed.json"
            malformed_map.write_text(
                '{"version": 1, "suites": {"netxduo": null}, "bundles": {}}',
                encoding="utf-8",
            )
            stderr = io.StringIO()
            with redirect_stderr(stderr):
                self.assertEqual(
                    2, classify_changes.main(["--map", str(malformed_map)])
                )
            self.assertIn("validation failed", stderr.getvalue())

            stdout = io.StringIO()
            stderr = io.StringIO()
            with redirect_stdout(stdout), redirect_stderr(stderr):
                self.assertEqual(
                    0,
                    classify_changes.main(
                        ["--files-from", str(temporary_path / "missing")]
                    ),
                )
            self.assertEqual("true", json.loads(stdout.getvalue())["full"])

            stdout = io.StringIO()
            with redirect_stdout(stdout):
                self.assertEqual(
                    0,
                    classify_changes.main(
                        ["--base", "missing", "--head", "also-missing"]
                    ),
                )
            self.assertEqual("true", json.loads(stdout.getvalue())["full"])

            output_file = temporary_path / "github-output"
            summary_file = temporary_path / "summary"
            self.assertEqual(
                0,
                classify_changes.main(
                    [
                        "--full-reason",
                        "manual dispatch",
                        "--github-output",
                        str(output_file),
                        "--summary",
                        str(summary_file),
                    ]
                ),
            )
            self.assertIn("full=true", output_file.read_text(encoding="utf-8"))
            self.assertIn("manual dispatch", summary_file.read_text(encoding="utf-8"))

    def test_classifier_exception_uses_internal_full_fallback(self):
        """Unexpected selection errors are converted into full classifier output."""
        expected = self.classify(forced_reason="classifier error")
        stderr = io.StringIO()
        stdout = io.StringIO()
        with mock.patch.object(
            classify_changes,
            "classify_files",
            side_effect=[ValueError("injected error"), expected],
        ):
            with redirect_stderr(stderr), redirect_stdout(stdout):
                result = classify_changes.main(["--full-reason", "test"])
        self.assertEqual(0, result)
        self.assertEqual(expected, json.loads(stdout.getvalue()))
        self.assertIn("selecting the full suite", stderr.getvalue())

    def test_script_main_guard_returns_success(self):
        """The executable classifier entry point delegates to main."""
        script = CI_DIRECTORY / "classify_changes.py"
        stdout = io.StringIO()
        with mock.patch.object(sys, "argv", [str(script), "--validate"]):
            with redirect_stdout(stdout):
                with self.assertRaises(SystemExit) as context:
                    runpy.run_path(str(script), run_name="__main__")
        self.assertEqual(0, context.exception.code)


class GateTests(unittest.TestCase):
    """Verify stable dev-gate aggregation semantics."""

    def test_successful_required_and_selected_jobs_pass(self):
        """Successful required/selected jobs and skipped unselected jobs pass."""
        diagnostics = check_dev_gate.validate_results(
            ["classify=success", "smoke=success"],
            ["mqtt=true:success", "web=false:skipped"],
        )
        self.assertEqual([], diagnostics)

    def test_failed_cancelled_and_unexpected_results_fail(self):
        """Failures, cancellations, and unexpected skip/run states are diagnosed."""
        diagnostics = check_dev_gate.validate_results(
            ["classify=failure", "smoke=cancelled"],
            [
                "mqtt=true:skipped",
                "web=true:failure",
                "ptp=false:success",
            ],
        )
        self.assertEqual(5, len(diagnostics))
        self.assertTrue(any("classify" in item for item in diagnostics))
        self.assertTrue(any("mqtt" in item for item in diagnostics))

    def test_malformed_assignments_are_rejected(self):
        """Malformed required and conditional assignments cannot pass the gate."""
        with self.assertRaises(ValueError):
            check_dev_gate.parse_assignment("missing-value")
        with self.assertRaises(ValueError):
            check_dev_gate.parse_conditional("job=maybe:success")
        with self.assertRaises(ValueError):
            check_dev_gate.parse_conditional("job=true")

    def test_gate_cli_exit_statuses(self):
        """The gate CLI returns zero, one, and two for pass, failure, and misuse."""
        stdout = io.StringIO()
        with redirect_stdout(stdout):
            self.assertEqual(
                0,
                check_dev_gate.main(
                    [
                        "--required",
                        "smoke=success",
                        "--conditional",
                        "web=false:skipped",
                    ]
                ),
            )
        self.assertIn("completed successfully", stdout.getvalue())

        stderr = io.StringIO()
        with redirect_stderr(stderr):
            self.assertEqual(
                1, check_dev_gate.main(["--required", "smoke=cancelled"])
            )
        self.assertIn("cancelled", stderr.getvalue())

        stderr = io.StringIO()
        with redirect_stderr(stderr):
            self.assertEqual(2, check_dev_gate.main(["--required", "bad"]))
        self.assertIn("Invalid job assignment", stderr.getvalue())

    def test_gate_script_main_guard_returns_success(self):
        """The executable gate entry point delegates to main."""
        script = CI_DIRECTORY / "check_dev_gate.py"
        arguments = [str(script), "--required", "smoke=success"]
        stdout = io.StringIO()
        with mock.patch.object(sys, "argv", arguments):
            with redirect_stdout(stdout):
                with self.assertRaises(SystemExit) as context:
                    runpy.run_path(str(script), run_name="__main__")
        self.assertEqual(0, context.exception.code)


if __name__ == "__main__":
    unittest.main()
