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

"""Validate required and conditionally selected dev CI job results."""

import argparse
import sys


def parse_assignment(assignment):
    """Split a name=value command-line assignment."""
    name, separator, value = assignment.partition("=")
    if not separator or not name or not value:
        raise ValueError(f"Invalid job assignment: {assignment}")
    return name, value


def parse_conditional(assignment):
    """Split a name=expected:result conditional assignment."""
    name, value = parse_assignment(assignment)
    expected_text, separator, result = value.partition(":")
    if not separator or expected_text not in {"true", "false"} or not result:
        raise ValueError(f"Invalid conditional job assignment: {assignment}")
    return name, expected_text == "true", result


def validate_results(required_assignments, conditional_assignments):
    """Return diagnostics for failed, cancelled, or unexpectedly skipped jobs."""
    diagnostics = []
    for assignment in required_assignments:
        name, result = parse_assignment(assignment)
        if result != "success":
            diagnostics.append(f"Required job {name} finished with {result}")
    for assignment in conditional_assignments:
        name, expected, result = parse_conditional(assignment)
        if expected and result != "success":
            diagnostics.append(f"Selected job {name} finished with {result}")
        elif not expected and result != "skipped":
            diagnostics.append(
                f"Unselected job {name} unexpectedly finished with {result}"
            )
    return diagnostics


def parse_arguments(arguments):
    """Parse command-line arguments."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--required", action="append", default=[])
    parser.add_argument("--conditional", action="append", default=[])
    return parser.parse_args(arguments)


def main(arguments=None):
    """Validate job results and return a failing status for any diagnostic."""
    options = parse_arguments(arguments)
    try:
        diagnostics = validate_results(options.required, options.conditional)
    except ValueError as error:
        print(error, file=sys.stderr)
        return 2
    if diagnostics:
        for diagnostic in diagnostics:
            print(diagnostic, file=sys.stderr)
        return 1
    print("All required dev CI jobs completed successfully.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
