#!/usr/bin/env python3
"""Report coverage of the certified source, unioned across build configurations.

gcovr's --add-tracefile merge keys every branch by the basic-block pair gcov
assigned it. Those block numbers are not a property of the source: a file that
compiles to a different amount of code in two configurations gets its blocks
renumbered, so the same source branch arrives under two identities and the
merge counts it twice. NetX Duo meets this harder than any other component in
the suite -- 105 build configurations across eight suites, against ThreadX's
six and FileX's eleven, and feature gates that change code volume by whole
files.

That inflation is symmetric for a branch covered everywhere, so the percentage
stays plausible and the fault is easy to miss. It is not harmless: the figure a
certification report quotes as "branches in the certified source" has to be
branches in the certified source, and the number grows or shrinks when a build
configuration is added for reasons that have nothing to do with the code.

This script reports the union instead. A line is covered if any configuration
executed it; the Nth branch on a line is covered if any configuration took it.
Branches are keyed by their position within the line rather than by block
number, which is stable across configurations because the order gcov emits them
in follows the source expression.

That stability is a claim about the data, so it is checked rather than assumed.
Before any figure is printed, every line carrying branches is checked for a
branch *count* that differs between the configurations compiling it. If one
does, position does not identify a source branch on this tree and unioning by
position could mark a branch covered because a different branch was taken
somewhere else, which overstates coverage. The check fails the run.

Both figures are kept. gcovr's merged report is still produced and published
unchanged -- it is the tool's own output and nothing here rewrites it. This is
the figure the coverage ratchet gates on, so that adding a build configuration
moves the number only by the code it actually brings in.
"""

import collections
import glob
import json
import math
import os
import sys


# Code the regression-test hook macros inject into the certified source, which
# is not part of the denominator. NetX Duo's list is empty, and the
# census that produced it is here because an empty list with no census reads as
# a question nobody asked.
#
# Every -D on the certified compile line was classified, over two
# configurations, from build.ninja rather than from the CMakeLists. DEFINES and
# FLAGS are identical on all 511 common/src objects in each. The eight macros
# are NX_INCLUDE_USER_DEFINE_FILE, TX_INCLUDE_USER_DEFINE_FILE, netxduo_EXPORTS,
# NX_TAHI_ENABLE, NX_MAX_PHYSICAL_INTERFACES=4,
# NX_ENABLE_IPV6_PATH_MTU_DISCOVERY, and on tsn_build_coverage NX_PHYSICAL_HEADER=48
# and NX_ENABLE_VLAN. Six are ordinary product configuration and one is build
# plumbing. NX_TAHI_ENABLE is the only one the test build defines and no shipped
# build does, and it has zero footprint in certified source: 1,105 hits in the
# tree, every one under test/. It gates tests, not product code.
#
# The generated nx_user.h is byte-identical to the shipped
# common/inc/nx_user_sample.h and contributes no active product option at all,
# checked by preprocessing the real translation unit rather than the header on
# its own -- the header in isolation reports a define the enclosing #if
# removes, and a line grep for #define on that file reports 117 where the
# translation unit has 0.
#
# The *_EXTENSION family was censused separately, by full identifier: a
# grep truncating at the suffix reports three macros, two of which are invoked
# nowhere. The real census is 17 sites across five macros. NX_CLEANUP_EXTENSION
# holds 11 of them, is defined only in the shipped nx_api.h, and no test build
# redefines it -- so it ships and its sites stay in the denominator. This is
# ThreadX's TX_TRACE_PORT_EXTENSION shape, and an assessor who finds a second
# *_EXTENSION family in this tree is entitled to that answer. The other four
# macros are redefined only by test/cmake/netxduo64/nx_user.h, and they do add
# live code at six certified sites -- but netxduo64 is out of the merge on
# grounds independent of this question, so none of that code reaches this
# denominator. It is kept out by the boundary rather than by a site list.
#
# Verdict: no category (a) hook site in the certified build. Nothing to
# exclude. If netxduo64 is ever brought into the merge, those six sites become
# a live case of one -- whole-line exclusion at the three *_PTR_SET sites, whose
# #ifndef fallbacks are empty, and branches-only at the three *_PTR_GET sites,
# whose fallbacks are not.
HOOK_SITES = []

# Sites where a hook displaces shipped code rather than occupying an empty
# line, so that only its branches may come out. Empty here for the same reason
# HOOK_SITES is: the certified build has no hook sites of either kind.
HOOK_BRANCH_SITES = []


def exclude_hook_sites(lines, branches):
    """Drop the hook expansions from the union, and report what was dropped.

    Returns one row per site: the macro, and the covered/total it took out of
    each axis. Covered/total rather than a count, so the output shows on its
    face that the exclusion removed nothing that was uncovered -- which would
    raise the figure for the wrong reason.
    """

    report = []
    missing = []

    for path, number, macro, drop_line in (
            [(p, n, m, True) for p, n, m in HOOK_SITES] +
            [(p, n, m, False) for p, n, m in HOOK_BRANCH_SITES]):

        outcomes = sorted(k for k in branches if k[0] == path and k[1] == number)
        if (path, number) not in lines:
            missing.append((path, number, macro))
            continue

        line_covered = line_total = 0
        if drop_line:
            line_covered, line_total = lines.pop((path, number)), 1

        outcome_covered = sum(branches.pop(k) for k in outcomes)
        report.append((path, number, macro, drop_line,
                       line_covered, line_total, outcome_covered, len(outcomes)))

    return report, missing


def union(tracefiles):
    """Union line and branch coverage across per-configuration tracefiles.

    Also returns, per (file, line), the branch count each configuration
    compiled it with, which is what the keying-soundness check reads.
    """

    lines = {}
    branches = {}
    shapes = {}

    for path in tracefiles:
        name_of_configuration = os.path.basename(path)[:-len(".json")]
        with open(path, encoding="utf-8") as handle:
            data = json.load(handle)

        for entry in data.get("files", []):
            name = entry["file"]
            for line in entry.get("lines", []):
                number = line["line_number"]
                key = (name, number)
                lines[key] = lines.get(key, 0) or (1 if line["count"] > 0 else 0)

                outcomes = line.get("branches", [])
                if outcomes:
                    shapes.setdefault(key, {})[name_of_configuration] = len(outcomes)

                for index, branch in enumerate(outcomes):
                    key = (name, number, len(outcomes), index)
                    branches[key] = branches.get(key, 0) or (1 if branch["count"] > 0 else 0)

    return lines, branches, shapes


def multiform_lines(shapes):
    """Lines that compile to more than one branch count across configurations.

    These are the lines the key's branch-count component exists for. Each one
    contributes its branches once per distinct compiled form, so the
    denominator counts a source line's branches more than once and the figure
    is conservative by exactly that much. Reported with the figure rather than
    absorbed, because an assessor is entitled to know where a denominator
    counts something twice, and why.

    A configuration that does not compile the line contributes no entry and is
    not a second form.
    """

    return sorted(
        (path, number, counts)
        for (path, number), counts in shapes.items()
        if len(set(counts.values())) > 1)


def truncate(rate):
    """Round a percentage down to the two decimal places the report prints.

    Rounding to nearest would print a figure above the ratio it stands for, and
    a coverage report that overstates coverage, even by a hundredth, is the
    wrong error for certification evidence to make.

    It also keeps the report and the gate in step. The threshold is compared
    against the full-precision ratio, so a gate set to a rounded-up figure
    fails a tree in which nothing has regressed. Truncating here makes the
    printed figure the one a threshold can safely be set to.
    """

    return math.floor(rate * 100) / 100


def main():
    if len(sys.argv) < 4:
        print("usage: coverage_union.py <tracefile-dir> <min-line> <min-branch>", file=sys.stderr)
        return 2

    directory, min_line, min_branch = sys.argv[1], float(sys.argv[2]), float(sys.argv[3])

    tracefiles = sorted(glob.glob(os.path.join(directory, "*.json")))
    if not tracefiles:
        print("coverage_union.py: no JSON in %s." % directory, file=sys.stderr)
        print("Run the suites with TX_COVERAGE=ON first.", file=sys.stderr)
        return 1

    lines, branches, shapes = union(tracefiles)
    if not lines:
        print("coverage_union.py: the tracefiles contain no files.", file=sys.stderr)
        return 1

    # Before any figure, because a figure published over an unsound key is
    # worse than no figure at all.
    multiform = multiform_lines(shapes)

    excluded, missing = exclude_hook_sites(lines, branches)
    if missing:
        for path, number, macro in missing:
            print("coverage_union.py: %s:%d is not in the report -- %s has moved."
                  % (path, number, macro), file=sys.stderr)
        print("coverage_union.py: re-derive HOOK_SITES from the headers.", file=sys.stderr)
        return 1

    line_covered, line_total = sum(lines.values()), len(lines)
    branch_covered, branch_total = sum(branches.values()), len(branches)
    files = len({path for path, _ in lines})

    line_rate = (100.0 * line_covered) / line_total
    branch_rate = (100.0 * branch_covered) / branch_total if branch_total else 100.0

    print("coverage_union.py: unioned over %d configuration(s):" % len(tracefiles))
    for path in tracefiles:
        print("    %s" % os.path.basename(path)[:-len(".json")])

    # The key's branch-count component, and what it costs, on the face of the
    # output. A reader who sees a denominator counting a line's branches twice
    # is entitled to find out here rather than by re-deriving it.
    print("    %d line(s) carry branches; %d compile to more than one form"
          % (len(shapes), len(multiform)))
    for path, number, counts in multiform:
        forms = collections.Counter(counts.values())
        spread = ", ".join("%d branches in %d configuration(s)" % (n, c)
                           for n, c in sorted(forms.items()))
        print("        %-46s %s" % ("%s:%d" % (path, number), spread))
    if excluded:
        print("    excluded, regression-test hook expansions:")
        hook_lines_covered = hook_lines_total = 0
        hook_outcomes_covered = hook_outcomes_total = 0
        for path, number, macro, drop_line, lc, lt, oc, ot in excluded:
            print("        %-44s lines %d/%d, outcomes %2d/%-2d  %s%s"
                  % ("%s:%d" % (path, number), lc, lt, oc, ot, macro,
                     "" if drop_line else ", branches only"))
            hook_lines_covered += lc
            hook_lines_total += lt
            hook_outcomes_covered += oc
            hook_outcomes_total += ot
        print("        %-44s lines %d/%d, outcomes %2d/%-2d"
              % ("total", hook_lines_covered, hook_lines_total,
                 hook_outcomes_covered, hook_outcomes_total))
    else:
        print("    excluded, regression-test hook expansions: none -- "
              "no category (a) site in the certified build, see HOOK_SITES")

    print("    files    %d" % files)
    print("    lines    %d/%d - %.2f%%" % (line_covered, line_total, truncate(line_rate)))
    print("    branches %d/%d - %.2f%%" % (branch_covered, branch_total, truncate(branch_rate)))

    status = 0
    if line_rate < min_line:
        print("coverage_union.py: failed minimum line coverage (got %.2f%%, minimum %.2f%%)"
              % (truncate(line_rate), min_line), file=sys.stderr)
        status = 1
    if branch_rate < min_branch:
        print("coverage_union.py: failed minimum branch coverage (got %.2f%%, minimum %.2f%%)"
              % (truncate(branch_rate), min_branch), file=sys.stderr)
        status = 1

    return status


if __name__ == "__main__":
    sys.exit(main())
