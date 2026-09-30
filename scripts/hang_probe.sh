#!/bin/bash

# Records the state of a regression test process that outlives a threshold, so that a
# ctest timeout leaves something to read. ctest SIGKILLs a timed-out test and discards
# what it had buffered, so the retained report carries the word "Timeout" and nothing
# else: no banner, no stdout, and Test.xml's Exit Code, Execution Time and Completion
# Status all empty. Which state the process was in has to be captured before it dies.
#
# Reads /proc and nothing else. It attaches no debugger and sends no signal, both of
# which matter: a stalled test has a thread parked in sigsuspend, and delivering any
# signal to it releases the process and destroys the evidence.
#
# Three samples twenty seconds apart, because the useful distinction is between a
# process that is stopped and one that is merely slow. A stalled test shows identical
# per-thread CPU counters across all three; a slow one shows them climbing.
#
# The threshold sits above the slowest test this suite has ever passed in CI --
# netx_rtcp_basic_test, measured at 177.87 to 423.08 seconds -- and below the harness
# ctest timeout of 1000, leaving time to take all three samples before the kill.

set -u

build_dir=$(realpath "${1:?usage: hang_probe.sh <build directory> [threshold seconds]}")
threshold=${2:-600}
out="$build_dir/hang_probe.txt"

hz=$(getconf CLK_TCK 2>/dev/null || echo 100)

declare -A reported

sample() {
    local pid=$1 name=$2 tag=$3
    {
        echo "=== $tag  $(date -Is)  test=$name pid=$pid"
        grep -E '^(State|Threads|SigPnd|ShdPnd|SigBlk)' "/proc/$pid/status" 2>/dev/null
        local t tid st
        for t in /proc/"$pid"/task/*; do
            tid=${t##*/}
            st=$(cat "$t/stat" 2>/dev/null) || continue
            # field 3 is the state, 14 and 15 are utime and stime in jiffies
            echo "  tid=$tid state=$(awk '{print $3}' <<<"$st")" \
                 "cpu=$(awk '{print $14"/"$15}' <<<"$st")" \
                 "wchan=$(cat "$t/wchan" 2>/dev/null)" \
                 "syscall=$(cat "$t/syscall" 2>/dev/null)"
        done
        # The load addresses, so a futex word in the syscall arguments above can be
        # resolved to a symbol offline without needing the live process.
        echo "  --- load addresses"
        grep -E ' r-xp .*(regression/|lib.*\.so)' "/proc/$pid/maps" 2>/dev/null | sed 's/^/  /'
    } >> "$out" 2>/dev/null
}

while true; do
    for pd in /proc/[0-9]*; do
        pid=${pd#/proc/}
        exe=$(readlink "$pd/exe" 2>/dev/null) || continue
        case "$exe" in "$build_dir"/*) ;; *) continue ;; esac
        [ -n "${reported[$pid]:-}" ] && continue
        # Elapsed from /proc rather than ps, which a minimal container may not carry.
        # Field 22 of stat is the start time in clock ticks since boot. The comm field
        # can itself contain spaces, so it is stripped first and the count restarts
        # after it, which puts start time at field 20 of the remainder.
        st=$(cat "$pd/stat" 2>/dev/null) || continue
        starttime=$(awk '{print $20}' <<<"${st#*) }" 2>/dev/null)
        [ -z "$starttime" ] && continue
        uptime=$(awk '{print int($1)}' /proc/uptime 2>/dev/null)
        elapsed=$(( uptime - starttime / hz ))
        if [ "$elapsed" -ge "$threshold" ]; then
            reported[$pid]=1
            name=$(basename "$exe")
            for k in 1 2 3; do
                kill -0 "$pid" 2>/dev/null || { echo "  exited before sample $k" >> "$out"; break; }
                sample "$pid" "$name" "sample $k"
                sleep 20
            done
            echo "" >> "$out"
        fi
    done
    sleep 5
done
