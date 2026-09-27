#!/bin/bash

# NetX Duo owns no test harness. The threadx clone supplies the runner, the
# CMake toolchain file and the ThreadX library the tests link against, and the
# filex clone supplies the FileX library. Every suite under this directory
# shares one pair of clones, so the refs are named here once rather than in
# each suite's run.sh, which sources this file.

threadx_url=https://github.com/eclipse-threadx/threadx.git
threadx_ref=v6.4.1_cert

# The released FileX baseline. Nothing of the harness reaches NetX Duo through
# this clone -- only library source -- so it names the tag rather than the
# certification branch, and a tag is already frozen.
filex_url=https://github.com/eclipse-threadx/filex.git
filex_ref=v6.4.1_rel

cmake_dir=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)

# True when the clone at $1 sits on ref $2. A shallow clone holds one commit,
# so HEAD says where the clone is and not what it was asked for. A branch pin
# leaves that branch checked out and is answered by its name; a tag pin leaves
# HEAD detached, and is answered by the tag resolving to HEAD. Asking only
# whether the tag exists would pass on any clone carrying the tag set.
on_ref()
{
    [ "$(git -C "$1" rev-parse --abbrev-ref HEAD 2>/dev/null)" = "$2" ] && return 0

    local tag_commit
    tag_commit=$(git -C "$1" rev-parse -q --verify "refs/tags/$2^{commit}" 2>/dev/null) || return 1
    [ "$tag_commit" = "$(git -C "$1" rev-parse HEAD 2>/dev/null)" ]
}

# Put $2 on ref $4, and report the commit it resolved to. A clone left behind
# by an earlier run is the one way a run that reports a pinned dependency can
# be using something else, so the ref is checked rather than the directory's
# existence.
pin_dependency()
{
    local description=$1
    local dir=$cmake_dir/$2
    local url=$3
    local ref=$4

    if [ -d "$dir" ]; then
        # Compared against the clone's own path because git searches upwards:
        # asked inside a directory that is not a clone, it answers for the
        # repository this tree sits in, and the dependency would be taken for
        # pinned.
        if [ "$(git -C "$dir" rev-parse --show-toplevel 2>/dev/null)" != "$dir" ]; then
            echo "$dir is not a git clone. Remove it and run again." >&2
            return 1
        fi

        if ! on_ref "$dir" "$ref"; then
            echo "$2 is not on $ref. Replacing the clone." >&2
            rm -rf "$dir" || return 1
            git -c advice.detachedHead=false clone "$url" --depth 1 --branch "$ref" "$dir" || return 1
        fi
    else
        git -c advice.detachedHead=false clone "$url" --depth 1 --branch "$ref" "$dir" || return 1
    fi

    echo "$description: $2 $ref at $(git -C "$dir" rev-parse --short HEAD)"
}

pin_threadx()
{
    pin_dependency "Test harness" threadx "$threadx_url" "$threadx_ref"
}

pin_filex()
{
    pin_dependency "Library dependency" filex "$filex_url" "$filex_ref"
}
