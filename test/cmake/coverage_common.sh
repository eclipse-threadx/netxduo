#!/bin/bash

# Shared coverage reporting for every suite under this directory.
#
# NetX Duo has ten test suites and one certified denominator. Six of the ten
# are named after an out-of-scope subject -- addons/web, addons/ptp,
# addons/mqtt, nx_secure, crypto_libraries -- and report on it, but every one
# of them compiles and executes the whole netxduo library, common/src
# included. Until this file existed each suite threw that data away, so six of
# the eight suites that contribute to the certified figure produced no
# certified-source data at all.
#
# Two report families come out of here and they are rooted differently, on
# purpose:
#
#   the subject report   what a suite covers of its own subject, which for six
#                        suites is out of the certified denominator. Rooted at
#                        the subject directory, so the file names in it are the
#                        ones that suite's report has always carried.
#
#   the certified report common/src less nx_ram_network_driver.c.
#                        Rooted at the repository root with -f confining it, so
#                        every suite names the same source file identically and
#                        the cross-suite union can key on that name.
#
# coverage_merge.sh unions the certified family across suites. Nothing here
# unions the subject family across anything: those are separate subjects.

# Both -r and the positional search path have to be absolute.
#
# A relative root resolved against whatever directory gcovr started in is how a
# report containing zero files and an exit status of 0 is produced, which is
# the worst failure available here -- an empty gcovr XML advertises
# line-rate="1.0" beside lines-valid="0", so every downstream consumer reads
# "no data" as "100% covered" and no threshold can catch it. The assertions
# below sit next to the paths that would cause it.
#
# --object-directory does not scope a report and is not used. Measured on
# this tree: pointing it at the whole netxduo.dir object tree with
# -r common/src gives the identical file set, while widening -r admits 322
# out-of-scope files. -r is the boundary; the positional path picks the build.
cov_repo_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd -P)
cov_suite=$(basename "$PWD")

# The certified denominator: common/src, all 511 files at v6.4.1_rel less
# nx_ram_network_driver.c, the harness's simulated Ethernet device -- 510.
#
# The exclusion names the one file by its absolute path and must keep doing so.
# A name pattern is not available here: fourteen files under common/src carry
# "driver" in their name and thirteen of them are certified source, including
# the four NX_ENABLE_TCPIP_OFFLOAD files that only instrumentation reaches.
# FileX's coverage.sh excludes its driver with ".*driver.*" because FileX has
# exactly one such file; copying that pattern to this tree would silently
# delete thirteen files from the denominator.
cov_certified_filter=$cov_repo_root/common/src
cov_certified_exclude=$cov_repo_root/common/src/nx_ram_network_driver.c

# Every suite builds the netxduo target into the same place, checked rather
# than assumed: all ten add_subdirectory the repository root as "netxduo", and
# PRODUCT is netxduo in the two CMakeLists that set it.
cov_certified_objdir()
{
    echo "$PWD/build/$1/netxduo/CMakeFiles/netxduo.dir/common/src"
}

# Fail on a report with no files in it, named so the message says which report.
cov_assert_nonempty()
{
    if ! grep -q "<class " "$1"; then
        echo "coverage.sh: $2 contains no files." >&2
        [ -n "$3" ] && echo "Expected gcda files under $3." >&2
        return 1
    fi
    return 0
}

# The suite's own subject, per configuration. $1 is the configuration, $2 the
# subject directory relative to the repository root.
#
# Rooted at the subject directory rather than at the repository root, so the
# names in these reports are exactly the names they have always carried. These
# figures are out of the certified denominator for six of the seven callers and
# nothing unions them with anything, so there is no reason to renumber them.
cov_report_subject()
{
    local config=$1 subject=$2
    shift 2

    local subject_abs=$cov_repo_root/$subject
    local objdir=$PWD/build/$config/netxduo/CMakeFiles/netxduo.dir/$subject
    local out=coverage_report/per_configuration

    mkdir -p "$out/$config"
    gcovr -r "$subject_abs" "$objdir" "$@" \
          --json "$out/$config.json" \
          --xml-pretty --output "$out/$config.xml"
    gcovr -r "$subject_abs" "$objdir" "$@" \
          --html --html-details --output "$out/$config/index.html"

    cov_assert_nonempty "$out/$config.xml" "the $cov_suite report for '$config'" "$objdir"
}

# The certified source, per configuration, keyed by suite and configuration.
#
# The key carries the suite name because two suites declare a configuration
# called default_build_coverage -- netxduo and netxduo64 -- and netxduo64 is
# the one whose data must not enter the merge. Keying by configuration alone
# would let it overwrite the one whose data must.
cov_report_certified()
{
    cov_report_certified_into per_configuration/certified "$1"
}

# netxduo64's certified-source report. It goes to a different directory, and
# that is the whole of the exclusion's enforcement.
#
# netxduo64 is out of the merge because it builds the certified source
# 64-bit, with no -m32, and three lines carry 0 branches at 32-bit and 2 at
# 64-bit, so unioning it by source position would mark branches covered that do
# not exist in the certified binary. coverage_merge.sh globs .../certified/ and
# nothing else. netxduo64's coverage.sh calls this function rather than the one
# above, so there is no argument it can be given that puts its data in the
# merge set -- the exclusion is a path it cannot be written into rather than a
# name someone has to remember to skip.
cov_report_informational()
{
    cov_report_certified_into per_configuration/informational "$1"
}

cov_report_certified_into()
{
    local out=coverage_report/$1 config=$2
    local objdir
    objdir=$(cov_certified_objdir "$config")
    local key=$cov_suite.$config

    mkdir -p "$out/$key"
    gcovr -r "$cov_repo_root" -f "$cov_certified_filter" -e "$cov_certified_exclude" "$objdir" \
          --json "$out/$key.json" \
          --xml-pretty --output "$out/$key.xml"
    gcovr -r "$cov_repo_root" -f "$cov_certified_filter" -e "$cov_certified_exclude" "$objdir" \
          --html --html-details --output "$out/$key/index.html"

    cov_assert_nonempty "$out/$key.xml" "the certified-source report for '$key'" "$objdir"
}

# crypto compiles no certified source, and this is the check that keeps that
# true rather than the comment that asserts it.
#
# Its CMakeLists filters the netxduo target's SOURCES down to crypto_libraries,
# so build/<config>/netxduo/CMakeFiles/netxduo.dir/common/src does not exist at
# all. That is why crypto is out of the merge on structural grounds and why the
# exclusion survives instrumenting every configuration. If the filter ever
# stops removing common/src, this fails and the suite gets reconsidered instead
# of quietly contributing nothing.
cov_assert_no_certified_objects()
{
    local objdir
    objdir=$(cov_certified_objdir "$1")

    local count=0
    [ -d "$objdir" ] && count=$(find "$objdir" -name '*.gcno' | wc -l)

    if [ "$count" -ne 0 ]; then
        echo "coverage.sh: $cov_suite compiled $count certified-source objects under" >&2
        echo "$objdir, where it is recorded as compiling none. The suite's exclusion" >&2
        echo "from the certified merge rests on that being zero." >&2
        return 1
    fi
    echo "coverage.sh: $cov_suite/$1 compiles 0 certified-source objects, as recorded."
    return 0
}

# The suite's own merged report, across its own configurations.
#
# This is what the regression template publishes: it reads
# <cmake_path>/coverage_report/merged.xml and moves coverage_report/merged to
# coverage_report/<result_affix> for Pages. No suite produced one before, so
# every suite job would have failed that step the first time CI ran.
#
# It is always the suite's own subject. A suite named after an addon publishes
# an addon figure and a suite whose subject is common/src publishes a
# certified-source figure; none of them publishes a partial certified
# percentage that could be read as the component's. The component's figure is
# a union across suites, it is computed once by coverage_merge.sh, and it is
# written one directory up under a different name.
#
# $1 is the tracefile directory relative to coverage_report/, $2 a label, $3
# the root the tracefiles were written against -- the subject directory for a
# subject merge, the repository root for a certified one. It has to match, or
# gcovr resolves the names in the tracefiles against the wrong directory.
cov_merge()
{
    local dir=coverage_report/$1 label=$2 root=$3

    shopt -s nullglob
    local tracefiles=("$dir"/*.json)
    shopt -u nullglob

    if [ ${#tracefiles[@]} -eq 0 ]; then
        echo "coverage.sh --merge: no JSON in $dir." >&2
        echo "Run the suite with TX_COVERAGE=ON first." >&2
        return 1
    fi

    local add_args=() t
    for t in "${tracefiles[@]}"; do
        add_args+=(--add-tracefile "$t")
    done

    mkdir -p coverage_report/merged
    gcovr -r "$root" "${add_args[@]}" --xml-pretty --output coverage_report/merged.xml
    gcovr -r "$root" "${add_args[@]}" --html --html-details \
          --output coverage_report/merged/index.html

    cov_assert_nonempty coverage_report/merged.xml "the merged $cov_suite report" || return 1

    # Named, not just counted. coverage_report/ is not cleaned between runs, so
    # a tracefile left by an earlier run over a different configuration set
    # would otherwise be merged in without anything saying so.
    echo "coverage.sh --merge: $cov_suite, $label, ${#tracefiles[@]} configuration(s):"
    for t in "${tracefiles[@]}"; do
        echo "    $(basename "$t" .json)"
    done
    return 0
}
