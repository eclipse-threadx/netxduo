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

"""Select NetX Duo CI profiles from a reliable Git change range."""

import argparse
import json
import re
import subprocess
import sys
from pathlib import Path


SCRIPT_DIRECTORY = Path(__file__).resolve().parent
REPOSITORY_ROOT = SCRIPT_DIRECTORY.parent.parent
DEFAULT_MAP = SCRIPT_DIRECTORY / "profile_map.json"
REVISION_PATTERN = re.compile(r"^[0-9a-fA-F]{40}$")
SUITE_OUTPUTS = {
    "web": "web_profiles",
    "ptp": "ptp_profiles",
    "mqtt": "mqtt_profiles",
    "mqtt_interoperability": "mqtt_interoperability_profiles",
    "netxduo64": "netxduo64_profiles",
    "netxduo_fast": "netxduo_fast_profiles",
    "nx_secure": "nx_secure_profiles",
    "nx_secure_interoperability": "nx_secure_interoperability_profiles",
    "crypto": "crypto_profiles",
}
NETX_64_REGRESSION_COMPONENTS = {"dhcp_test", "dns_test", "netxduo_test"}
NETX_REGRESSION_COMPONENTS = {
    "auto_ip_test",
    "bsd_test",
    "cloud_test",
    "ftp_test",
    "http_test",
    "mdns_test",
    "nat_test",
    "pop3_test",
    "ppp_test",
    "pppoe_test",
    "rtp_test",
    "rtsp_test",
    "smtp_test",
    "snmp_test",
    "sntp_test",
    "tahi_test",
    "telnet_test",
    "tftp_test",
    "tsn_test",
    "websocket_test",
}


class ProfileMapError(ValueError):
    """Indicate an inconsistent checked-in profile map."""


class Selection:
    """Accumulate profile bundles and render stable workflow outputs."""

    def __init__(self, profile_map):
        """Initialize an empty selection for the supplied profile map."""
        self.profile_map = profile_map
        self.selected = {suite: set() for suite in profile_map["suites"]}
        self.full_suites = set()
        self.reasons = []
        self.full = False

    def add_reason(self, reason):
        """Append a reason once while preserving discovery order."""
        if reason not in self.reasons:
            self.reasons.append(reason)

    def add_bundle(self, bundle_name, reason):
        """Merge one named profile bundle into the selection."""
        bundle = self.profile_map["bundles"][bundle_name]
        for suite, profiles in bundle.items():
            if profiles == "all":
                self.full_suites.add(suite)
                self.selected[suite].clear()
            elif suite not in self.full_suites:
                self.selected[suite].update(profiles)
        self.add_reason(reason)

    def select_suite(self, suite, reason):
        """Select every profile in one suite."""
        self.full_suites.add(suite)
        self.selected[suite].clear()
        self.add_reason(reason)

    def select_full(self, reason):
        """Select all declared profiles in every suite."""
        self.full = True
        self.full_suites.update(self.profile_map["suites"])
        for profiles in self.selected.values():
            profiles.clear()
        self.add_reason(reason)

    def _netxduo_matrix(self):
        """Shard selected NetX Duo profiles without duplicating the smoke profile."""
        netxduo = self.profile_map["suites"]["netxduo"]
        smoke = netxduo["smoke"]
        if "netxduo" in self.full_suites:
            selected_profiles = set(netxduo["profiles"])
        else:
            selected_profiles = set(self.selected["netxduo"])
        selected_profiles.discard(smoke)

        matrix = []
        for shard in netxduo["shards"]:
            profiles = [
                profile
                for profile in shard["profiles"]
                if profile in selected_profiles
            ]
            if profiles:
                matrix.append(
                    {
                        "name": shard["name"],
                        "profiles": " ".join(profiles),
                        "result_name": "Dev-NetXDuo-" + shard["name"],
                    }
                )
                selected_profiles.difference_update(profiles)
        if selected_profiles:
            raise ProfileMapError(
                "NetX Duo profiles are missing from the shard map: "
                + ", ".join(sorted(selected_profiles))
            )
        return matrix

    def outputs(self, changed_file_count):
        """Return compact values suitable for GitHub job outputs."""
        outputs = {
            "full": str(self.full).lower(),
            "reason": "; ".join(self.reasons) if self.reasons else "smoke only",
            "changed_files": str(changed_file_count),
            "netxduo_matrix": json.dumps(
                self._netxduo_matrix(), separators=(",", ":")
            ),
        }
        for suite, output_name in SUITE_OUTPUTS.items():
            if suite in self.full_suites:
                outputs[output_name] = "all"
            else:
                suite_order = self.profile_map["suites"][suite]["profiles"]
                outputs[output_name] = " ".join(
                    profile
                    for profile in suite_order
                    if profile in self.selected[suite]
                )
        return outputs


def parse_cmake_profiles(cmake_file):
    """Read BUILD_CONFIGURATIONS from one suite CMake file."""
    contents = cmake_file.read_text(encoding="utf-8")
    match = re.search(
        r"set\s*\(\s*BUILD_CONFIGURATIONS\b(.*?)\)", contents, re.DOTALL
    )
    if match is None:
        raise ProfileMapError(f"No BUILD_CONFIGURATIONS in {cmake_file}")
    return re.findall(r"\b[A-Za-z0-9_]*build[A-Za-z0-9_]*\b", match.group(1))


def load_profile_map(map_file):
    """Load and structurally validate the profile map."""
    with map_file.open(encoding="utf-8") as profile_map_stream:
        profile_map = json.load(profile_map_stream)
    validate_profile_map(profile_map)
    return profile_map


def validate_profile_map(profile_map, repository_root=REPOSITORY_ROOT):
    """Validate bundles, suite declarations, and the NetX Duo shard partition."""
    if profile_map.get("version") != 1:
        raise ProfileMapError("Unsupported profile map version")
    suites = profile_map.get("suites")
    bundles = profile_map.get("bundles")
    if not isinstance(suites, dict) or not isinstance(bundles, dict):
        raise ProfileMapError("Profile map must contain suites and bundles")
    if set(suites) != {"netxduo", *SUITE_OUTPUTS}:
        raise ProfileMapError("Profile map suite set does not match the worker suites")

    for suite, configuration in suites.items():
        profiles = configuration.get("profiles")
        if (
            not isinstance(profiles, list)
            or not profiles
            or len(profiles) != len(set(profiles))
        ):
            raise ProfileMapError(f"Invalid or duplicate profiles for {suite}")
        cmake_file = repository_root / "test" / "cmake" / suite / "CMakeLists.txt"
        cmake_profiles = parse_cmake_profiles(cmake_file)
        if profiles != cmake_profiles:
            raise ProfileMapError(f"Profile map is stale for {suite}")

    netxduo = suites["netxduo"]
    smoke = netxduo.get("smoke")
    shards = netxduo.get("shards")
    if smoke not in netxduo["profiles"] or not isinstance(shards, list):
        raise ProfileMapError("Invalid NetX Duo smoke profile or shards")
    sharded_profiles = [profile for shard in shards for profile in shard["profiles"]]
    if len(sharded_profiles) != len(set(sharded_profiles)):
        raise ProfileMapError("NetX Duo shard profiles are duplicated")
    if set(sharded_profiles) != set(netxduo["profiles"]):
        raise ProfileMapError("NetX Duo shards do not cover every profile")
    shard_names = [shard["name"] for shard in shards]
    if len(shard_names) != len(set(shard_names)):
        raise ProfileMapError("NetX Duo shard names are duplicated")

    for bundle_name, bundle in bundles.items():
        if not isinstance(bundle, dict) or not bundle:
            raise ProfileMapError(f"Empty profile bundle: {bundle_name}")
        for suite, profiles in bundle.items():
            if suite not in suites:
                raise ProfileMapError(f"Unknown suite {suite} in bundle {bundle_name}")
            if profiles == "all":
                continue
            if not isinstance(profiles, list) or not profiles:
                raise ProfileMapError(f"Invalid profiles in bundle {bundle_name}")
            unknown_profiles = set(profiles).difference(suites[suite]["profiles"])
            if unknown_profiles:
                raise ProfileMapError(
                    f"Unknown profiles in bundle {bundle_name}: "
                    + ", ".join(sorted(unknown_profiles))
                )


def _is_ipv6_source(filename):
    """Return whether one common source file is IPv6-specific."""
    return filename.startswith(
        (
            "nx_ipv6_",
            "nx_icmpv6_",
            "nx_nd_",
            "nxd_ipv6_",
            "nxd_icmpv6_",
            "nxd_nd_",
            "nxde_ipv6_",
            "nxde_icmpv6_",
            "nxde_nd_",
        )
    ) or "ping6" in filename


def _is_ipv4_source(filename):
    """Return whether one common source file is IPv4-specific."""
    return filename.startswith(
        ("nx_arp_", "nx_rarp_", "nx_igmp_", "nx_ipv4_", "nx_icmpv4_")
    )


def _classify_regression_path(path, selection):
    """Route a path below test/regression to every suite compiling it."""
    parts = path.split("/")
    if len(parts) < 3:
        selection.select_full("broad regression change")
        return
    component = parts[2]
    if component == "interoperability_test":
        if len(parts) < 4:
            selection.select_full("broad interoperability regression change")
        elif parts[3] == "mqtt_test":
            selection.add_bundle(
                "mqtt_interoperability_regression", "MQTT interoperability regression"
            )
        elif parts[3] == "nx_secure_test":
            selection.add_bundle(
                "secure_interoperability_regression",
                "secure interoperability regression",
            )
        elif parts[3] == "test_frame":
            selection.add_bundle(
                "interoperability_framework", "shared interoperability framework"
            )
        else:
            selection.select_full("unknown interoperability regression path")
    elif component in NETX_64_REGRESSION_COMPONENTS:
        selection.add_bundle("netx_64_regression", component)
    elif component in NETX_REGRESSION_COMPONENTS:
        selection.add_bundle("netx_regression", component)
    elif component == "ptp_test":
        selection.add_bundle("ptp_regression", component)
    elif component == "mqtt_test":
        selection.add_bundle("mqtt_regression", component)
    elif component in {"nx_secure_test", "crypto_test"}:
        selection.add_bundle("secure_regression", component)
    elif component == "web_test":
        selection.add_bundle("web_regression", component)
    elif component == "test":
        selection.select_full("shared regression utility")
    else:
        selection.select_full("unknown regression component")


def _classify_cmake_path(path, selection, profile_map):
    """Route suite-local CMake changes or fall back for shared infrastructure."""
    parts = path.split("/")
    if len(parts) < 3 or parts[2] not in profile_map["suites"]:
        selection.select_full("shared or unknown test CMake change")
    else:
        suite = parts[2]
        consumers = {
            "netxduo": ("netxduo", "netxduo64", "netxduo_fast", "ptp"),
            "mqtt": ("mqtt", "mqtt_interoperability"),
            "nx_secure": ("nx_secure", "nx_secure_interoperability"),
        }.get(suite, (suite,))
        for consumer in consumers:
            selection.select_suite(consumer, f"{suite} CMake suite")


def classify_path(path, selection):
    """Classify one repository-relative changed path."""
    if (
        not path
        or path.startswith("/")
        or "\\" in path
        or any(part in {"", ".", ".."} for part in path.split("/"))
        or any(ord(character) < 32 for character in path)
    ):
        selection.select_full("malformed changed path")
    elif path.startswith(("docs/", "samples/")):
        selection.add_reason("documentation or samples")
    elif path.startswith("common/inc/"):
        selection.select_full("public NetX Duo header")
    elif path.startswith("common/src/"):
        filename = path.rsplit("/", 1)[-1].lower()
        if _is_ipv6_source(filename):
            selection.add_bundle("netx_ipv6", "IPv6-specific NetX Duo source")
        elif _is_ipv4_source(filename):
            selection.add_bundle("netx_ipv4", "IPv4-specific NetX Duo source")
        else:
            selection.add_bundle("netx_shared", "shared NetX Duo source")
        selection.add_bundle("dependent_defaults", "dependent default profiles")
    elif path.startswith("addons/mqtt/"):
        selection.add_bundle("mqtt", "MQTT add-on")
    elif path.startswith("addons/websocket/"):
        selection.add_bundle("websocket", "WebSocket add-on")
    elif path.startswith(("addons/web/", "addons/http/")):
        selection.add_bundle("web_http", "Web or HTTP add-on")
    elif path.startswith(("addons/ptp/", "tsn/")):
        selection.add_bundle("ptp_tsn", "PTP or TSN component")
    elif path.startswith("addons/azure_iot/"):
        selection.select_full("retired Azure IoT component")
    elif path.startswith("addons/cloud/"):
        selection.add_bundle("netx_addon", "cloud add-on")
        selection.add_bundle("mqtt", "cloud MQTT consumers")
    elif path.startswith("addons/"):
        selection.add_bundle("netx_addon", "NetX Duo add-on")
    elif path.startswith("nx_secure/"):
        selection.add_bundle("secure", "NetX Secure component")
    elif path.startswith("crypto_libraries/"):
        selection.add_bundle("crypto", "cryptography component")
    elif path.startswith("test/regression/"):
        _classify_regression_path(path, selection)
    elif path.startswith("test/cmake/"):
        _classify_cmake_path(path, selection, selection.profile_map)
    elif path.startswith("utility/"):
        selection.add_bundle("netx_addon", "NetX Duo utility")
    elif path in {"CMakeLists.txt", ".gitmodules", "addons/CMakeLists.txt"}:
        selection.select_full("root or shared build configuration")
    elif path.startswith(
        (".github/", ".devcontainer/", "cmake/", "ports/", "scripts/", "test/")
    ):
        selection.select_full("shared CI, toolchain, script, port, or test change")
    else:
        selection.select_full("unknown path")


def classify_files(paths, profile_map, forced_reason=None):
    """Classify changed paths, with an optional conservative full override."""
    selection = Selection(profile_map)
    normalized_paths = list(paths)
    if forced_reason is not None:
        selection.select_full(forced_reason)
    else:
        for path in normalized_paths:
            classify_path(path, selection)
            if selection.full:
                break
    return selection.outputs(len(normalized_paths))


def changed_files_from_git(base_revision, head_revision, repository_root=REPOSITORY_ROOT):
    """Return NUL-safe changed paths, or None for an unreliable Git range."""
    if (
        not base_revision
        or not head_revision
        or REVISION_PATTERN.fullmatch(base_revision) is None
        or REVISION_PATTERN.fullmatch(head_revision) is None
        or set(base_revision) == {"0"}
    ):
        return None
    try:
        resolved = []
        for revision in (base_revision, head_revision):
            result = subprocess.run(
                ["git", "rev-parse", "--verify", f"{revision}^{{commit}}"],
                cwd=repository_root,
                check=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL,
                text=True,
            )
            resolved.append(result.stdout.strip())
        diff = subprocess.run(
            [
                "git",
                "diff",
                "--name-only",
                "--diff-filter=ACMRD",
                "-z",
                resolved[0],
                resolved[1],
                "--",
            ],
            cwd=repository_root,
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
        )
        return [item.decode("utf-8") for item in diff.stdout.split(b"\0") if item]
    except (OSError, subprocess.CalledProcessError, UnicodeDecodeError):
        return None


def write_github_outputs(output_file, outputs):
    """Append single-line classifier values to GITHUB_OUTPUT."""
    with output_file.open("a", encoding="utf-8") as output_stream:
        for name, value in outputs.items():
            output_stream.write(f"{name}={value}\n")


def write_summary(summary_file, outputs, paths):
    """Append a human-readable routing summary to the workflow summary."""
    with summary_file.open("a", encoding="utf-8") as summary_stream:
        summary_stream.write("## Dev CI routing\n\n")
        summary_stream.write(f"Reason: {outputs['reason']}\n\n")
        summary_stream.write(f"Changed files: {outputs['changed_files']}\n\n")
        summary_stream.write("| Suite | Profiles |\n| --- | --- |\n")
        summary_stream.write("| NetXDuo smoke | default_build_coverage |\n")
        summary_stream.write(
            "| NetXDuo additional | "
            + (outputs["netxduo_matrix"] if outputs["netxduo_matrix"] != "[]" else "none")
            + " |\n"
        )
        for suite, output_name in SUITE_OUTPUTS.items():
            summary_stream.write(
                f"| {suite} | {outputs[output_name] if outputs[output_name] else 'none'} |\n"
            )
        if paths:
            summary_stream.write("\nChanged paths:\n\n")
            for path in paths[:50]:
                safe_path = "".join(
                    character if ord(character) >= 32 else "?" for character in path
                ).replace("`", "'")
                summary_stream.write(f"- `{safe_path}`\n")
            if len(paths) > 50:
                summary_stream.write(f"- ... and {len(paths) - 50} more\n")


def parse_arguments(arguments):
    """Parse command-line arguments."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--map", type=Path, default=DEFAULT_MAP)
    parser.add_argument("--base")
    parser.add_argument("--head")
    parser.add_argument("--files-from", type=Path)
    parser.add_argument("--full-reason")
    parser.add_argument("--github-output", type=Path)
    parser.add_argument("--summary", type=Path)
    parser.add_argument("--validate", action="store_true")
    return parser.parse_args(arguments)


def main(arguments=None):
    """Validate the map or classify files for local and GitHub use."""
    options = parse_arguments(arguments)
    try:
        profile_map = load_profile_map(options.map)
    except (
        AttributeError,
        KeyError,
        OSError,
        TypeError,
        json.JSONDecodeError,
        ProfileMapError,
    ) as error:
        print(f"Profile map validation failed: {error}", file=sys.stderr)
        return 2
    if options.validate:
        print("Profile map validation passed.")
        return 0

    if options.files_from is not None:
        try:
            paths = options.files_from.read_text(encoding="utf-8").splitlines()
        except (OSError, UnicodeDecodeError) as error:
            print(f"Unable to read changed paths: {error}", file=sys.stderr)
            paths = []
            options.full_reason = "unreadable changed-path input"
    elif options.full_reason is not None:
        paths = []
    else:
        paths = changed_files_from_git(options.base, options.head)
        if paths is None:
            paths = []
            options.full_reason = "unreliable Git change range"

    try:
        outputs = classify_files(paths, profile_map, options.full_reason)
    except (KeyError, ProfileMapError, TypeError, ValueError) as error:
        print(f"Classifier error, selecting the full suite: {error}", file=sys.stderr)
        outputs = classify_files([], profile_map, "classifier error")
        paths = []

    if options.github_output is not None:
        write_github_outputs(options.github_output, outputs)
    else:
        print(json.dumps(outputs, indent=2, sort_keys=True))
    if options.summary is not None:
        write_summary(options.summary, outputs, paths)
    return 0


if __name__ == "__main__":
    sys.exit(main())
