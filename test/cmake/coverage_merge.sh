#!/bin/bash

# The NetX Duo certification coverage figure.
#
# Every suite's own coverage.sh --merge produces a merged report for that
# suite's own subject, and the regression template publishes it per job. Ten
# such reports are a real and useful artefact and none of them is this number.
#
# This one is a union across the eight suites that build the certified source
# 32-bit. A construct reached only by the web suite counts; a construct reached
# only in v6_no_frag_build counts. Nothing in the shared regression template
# produces it, because ThreadX never needed it: ThreadX merges configurations
# within one suite, and its suite is its component.
#
# It is computed here, in this repository, rather than in the shared template's
# Deploy job. Deploy exists to publish Pages, it is invoked with skip_test and
# has no build tree, and putting a component-specific denominator inside a
# workflow four repositories share would make every other component carry it.
# In CI this runs in a job of its own that needs the eight suite jobs and
# downloads their per-configuration tracefiles; run by hand it reads them off
# the local build trees. Either way the inputs are the same files and the log
# names them.

set -e

cd "$(dirname "$(realpath "$0")")"
repo_root=$(cd ../.. && pwd -P)

# The merge set is a path, not a list. Eight suites write their certified
# tracefiles into per_configuration/certified/ and netxduo64 writes into
# per_configuration/informational/, so that exclusion is expressed by the
# glob rather than by a name this script has to remember to skip. crypto writes
# neither: it compiles no certified source and asserts that on every run.
#
# TRACEFILE_DIR overrides the source for CI, where the tracefiles arrive as
# downloaded artifacts rather than as build output. The artifacts keep the
# certified/ and informational/ split, so the same rule applies there.
if [ -n "$TRACEFILE_DIR" ]; then
    inputs=("$TRACEFILE_DIR"/*.json)
else
    shopt -s nullglob
    inputs=(*/coverage_report/per_configuration/certified/*.json)
    shopt -u nullglob
fi

if [ ${#inputs[@]} -eq 0 ]; then
    echo "coverage_merge.sh: no certified tracefiles found." >&2
    echo "Run the suites with TX_COVERAGE=ON first." >&2
    exit 1
fi

# The merge set has to be complete, and that is asserted rather than trusted.
#
# Instrumentation has two switches -- TX_COVERAGE, and the build-type name
# match kept for the pinned runner's sake -- so a run with TX_COVERAGE unset
# still instruments the configurations whose names end in _coverage and still
# writes their tracefiles here. Without this check that run would produce a
# union over 32 of the 105 contributing configurations, print a plausible
# percentage, and nothing would say it was not the component's figure. The same
# applies to a CI run in which one suite job failed and uploaded nothing.
#
# The expected set is derived from each suite's CMakeLists with the same parser
# cmake_bootstrap.sh uses to decide what to build, so the two cannot disagree
# about what a suite's configurations are.
expected=()
for suite in netxduo netxduo_fast web ptp mqtt mqtt_interoperability \
             nx_secure nx_secure_interoperability; do
    configurations=$(sed -n "/(BUILD_CONFIGURATIONS/,/)/p" "$suite/CMakeLists.txt" \
        | sed ':label;N;s/\n/ /;b label' \
        | grep -Pzo "[a-zA-Z0-9_]*build[a-zA-Z0-9_]*\s*" | tr -d '\0')
    for configuration in $configurations; do
        # Configurations a suite reports informationally rather than into the
        # merge are declared in that suite's coverage.sh, which is the one place
        # the exclusion lives. Reading it here keeps the expected set and the
        # written set derived from the same declaration.
        case " $(sed -n 's/^INFORMATIONAL="\(.*\)"$/\1/p' "$suite/coverage.sh") " in
            *" $configuration "*) continue ;;
        esac
        expected+=("$suite.$configuration")
    done
done

present=" $(for t in "${inputs[@]}"; do basename "$t" .json; done | tr '\n' ' ')"
absent=()
for key in "${expected[@]}"; do
    case "$present" in
        *" $key "*) ;;
        *) absent+=("$key") ;;
    esac
done

if [ ${#absent[@]} -ne 0 ]; then
    echo "coverage_merge.sh: the merge set is incomplete -- ${#inputs[@]} tracefile(s)" >&2
    echo "for ${#expected[@]} contributing configurations. Missing:" >&2
    for key in "${absent[@]}"; do
        echo "    $key" >&2
    done
    echo "A union over part of the configuration set is not the component's figure." >&2
    echo "Re-run the missing suites with TX_COVERAGE=ON, or set" >&2
    echo "NX_COVERAGE_ALLOW_PARTIAL=1 to compute an explicitly partial figure." >&2
    [ "${NX_COVERAGE_ALLOW_PARTIAL:-0}" = "1" ] || exit 1

    # A partial figure is useful while iterating on one subsystem, and it must
    # never be able to occupy the path the component's figure occupies. So it
    # is not a warning on an otherwise identical artefact: it is written under a
    # different name, and the complete report is left untouched wherever it sits.
    #
    # This is the same enforcement used for netxduo64 and
    # optimize_build -- a path the wrong data cannot be written into, rather
    # than a label a reader has to notice. A stderr line does not survive being
    # copied into an evidence pack; a file name does.
    name=netxduo_certified_PARTIAL
    echo "coverage_merge.sh: PARTIAL -- ${#inputs[@]} of ${#expected[@]} configurations." >&2
    echo "Writing $name.xml. This is not the NetX Duo coverage figure." >&2
fi

# The gate is not set here. The first threshold comes from the figure a
# complete run measures, and rises as the coverage work closes gaps. Until then
# the run reports and does not fail on the number.
min_line=${NX_COVERAGE_MIN_LINE:-0}
min_branch=${NX_COVERAGE_MIN_BRANCH:-0}

out=coverage_report
name=${name:-netxduo_certified}
mkdir -p "$out/$name"

add_args=()
for t in "${inputs[@]}"; do
    add_args+=(--add-tracefile "$t")
done

# gcovr's own merged report, published unchanged beside the union. It
# is the tool's own output and nothing here rewrites it. Its branch denominator
# is not the source's: --add-tracefile keys each branch by the basic-block pair
# gcov assigned it, and a file that compiles to a different amount of code in
# two configurations has its blocks renumbered, so one source branch arrives
# under several identities. Publishing only the union would put a
# post-processed number in the evidence with the tool's output withheld;
# publishing only the merged figure would quote a denominator that is not the
# source's. Both, and the note reconciles them.
#
# -r is the repository root and the tracefiles were written against it, so the
# names resolve. It is not widened past that and no filter is reapplied here:
# the certified denominator was applied once, where the tracefiles were written, so
# the merged report and the union are computed from exactly the same filtered
# data rather than from two filters that could drift apart.
gcovr -r "$repo_root" "${add_args[@]}" --xml-pretty --output "$out/$name.xml"
gcovr -r "$repo_root" "${add_args[@]}" --html --html-details \
      --output "$out/$name/index.html"

if ! grep -q "<class " "$out/$name.xml"; then
    echo "coverage_merge.sh: the merged report contains no files." >&2
    exit 1
fi

# Named, not just counted. coverage_report/ is not cleaned between runs, so a
# tracefile left behind by an earlier run over a different configuration set
# would otherwise be merged in without anything saying so.
echo "coverage_merge.sh: $name, ${#inputs[@]} configuration(s):"
for t in "${inputs[@]}"; do
    echo "    $(basename "$t" .json)"
done

# Run after the reports are written, so a failed gate still leaves behind the
# reports that explain it.
staged=$(mktemp -d)
trap 'rm -rf "$staged"' EXIT
for t in "${inputs[@]}"; do
    cp "$t" "$staged/$(basename "$t")"
done
python3 ./coverage_union.py "$staged" "$min_line" "$min_branch"
