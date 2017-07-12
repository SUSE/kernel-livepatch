#!/bin/bash

#
# register-patches.sh -- add subpatches to KGraft patch
#
# Copyright (c) 2017 SUSE
#  Author: Nicolai Stange <nstange@suse.de>
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, see <http://www.gnu.org/licenses/>.
#

# This script expects a kGraft subpatch to live in a subdirectory
# SUBPATCH and to provide a SUBPATCH/livepatch_SUBPATCH.h
# header.
#
# This header must provide declarations for
# - klp_patch_SUBPATCH_init()
# - klp_patch_SUBPATCH_cleanup()
# and an (all uppercase) KLP_PATCH_SUBPATCH_FUNCS macro.
# The latter should be a comma separated list of KGR_PATCH*() entries,
# each corresponding to a function the subpatch wants to replace.
#
# Usage:
#   register-patches.sh livepatch_main.c kgraft-patch.spec
#
# This will properly substitute a number of placeholders in-place.
#

livepatch_main_file="$1"
livepatch_spec_file="$2"


# Generate list of patches
declare -a livepatches
for d in *; do
	[ -d "$d" ] || continue
	[ x"$d" = xrpm -o x"$d" = xscripts -o x"$d" = xuname_patch ] && continue
	[ -e "$d/livepatch_main.c" ] && continue  # this is some builddir

	if [ ! -f "$d/livepatch_${d}.h" ]; then
	    echo "error: $d/ doesn't have a $d/livepatch_${d}.h" 1>&2
	    exit 1
	fi

	livepatches[${#livepatches[@]}]=$(basename $d)
done

# Sort it
livepatches=($(
	for p in "${livepatches[@]}"; do
		echo $p
	done | sort))


# Finish livepatch_main.c:
## Add includes of per-patch headers.
KLP_PATCHES_INCLUDES=$(
	echo -n "/* Auto expanded KLP_PATCHES_INCLUDES: */\n"
	for p in "${livepatches[@]}"; do
		echo -n "#include \"${p}/livepatch_${p}.h\"\n"
	done)

## Add the individual patches' replacement entries to struct livepatch.
KLP_PATCHES_FUNCS=$(
	echo -n "\t\t/* Auto expanded KLP_PATCHES_FUNCS: */\n"
	for p in "${livepatches[@]}"; do
		p="KLP_PATCH_$(echo $p | tr '[:lower:]' '[:upper:]')_FUNCS"
		echo -n "\t\t${p}\n"
	done | sed 's/\\n$//' # rm trailing extra newlines
)

## Initialize the individual patches in livepatch_init().
KLP_PATCHES_INIT_CALLS=$(
	echo -n "\t/* Auto expanded KLP_PATCHES_INIT_CALLS: */\n"
	for p in "${livepatches[@]}"; do
		cat <<EOF
	retval = livepatch_${p}_init();
	if (retval)
		goto err_${p};

EOF
	done | sed 's%\t%\\t%g' | sed 's%$%\\n%g' | tr -d '\n' \
		    | sed 's/\(\\n\)\?\\n$//' # rm trailing extra newlines
)

## Setup the rollback error handlers in livepatch_init().
KLP_PATCHES_INIT_ERR_HANDLERS=$(
	echo -n "\t/* Auto expanded KLP_PATCHES_INIT_ERR_HANDLERS: */\n"
	for i in $(seq $((${#livepatches[@]} - 1)) -1 0); do
	    cat <<EOF
	livepatch_${livepatches[$i]}_cleanup();
err_${livepatches[$i]}:
EOF
	done | sed 's%\t%\\t%g' | sed 's%$%\\n%g' | tr -d '\n';
	echo "\treturn retval;"
)

## Cleanup the individual patches in livepatch_cleanup().
KLP_PATCHES_CLEANUP_CALLS=$(
	echo -n "\t/* Auto expanded KLP_PATCHES_CLEANUP_CALLS: */\n"
	for p in "${livepatches[@]}"; do
		echo -n "\tlivepatch_${p}_cleanup();\n"
	done)

sed -i -f - "$livepatch_main_file" <<EOF
s%@@KLP_PATCHES_INCLUDES@@%$KLP_PATCHES_INCLUDES%;
s%\s*@@KLP_PATCHES_FUNCS@@,\?%$KLP_PATCHES_FUNCS%;
s%\s*@@KLP_PATCHES_INIT_CALLS@@;\?%$KLP_PATCHES_INIT_CALLS%;
s%\s*@@KLP_PATCHES_INIT_ERR_HANDLERS@@:\?%$KLP_PATCHES_INIT_ERR_HANDLERS%;
s%\s*@@KLP_PATCHES_CLEANUP_CALLS@@;\?%$KLP_PATCHES_CLEANUP_CALLS%;
s%\s*@@KLP_PATCHES_CLEANUP_CALLS@@;\?%$KLP_PATCHES_CLEANUP_CALLS%;
EOF


# Finish kgraft-patch.spec:
## Enumerate the per subpatch source *.tar.bz2.
## Note: Start with Source7
S=7
## First check that none of the to be occupied Source<n> slots has
## been used already.
for i in "${!livepatches[@]}"; do
    if grep -q "^\s*Source$((i+S))\s*:" "$livepatch_spec_file"; then
	echo "error: Source$((i+S)) already used in $livepatch_spec_file" 1>&2
	exit 1;
    fi
done

KLP_PATCHES_SOURCES=$(
	echo -n "# Auto expanded KLP_PATCHES_SOURCES:\n"
	for i in "${!livepatches[@]}"; do
		echo -n "Source$((i+S)):\t${livepatches[i]}.tar.bz2\n"
	done | sed 's/\\n$//' # rm trailing extra newlines
)

## And extract them from %prep
KLP_PATCHES_SETUP_SOURCES=$(
	echo -n "# Auto expanded KLP_PATCHES_SETUP_SOURCES:\n"
	if [ ${#livepatches[@]} -gt 0 ]; then
	    echo -n '%setup -T -D'
	    for i in "${!livepatches[@]}"; do
		echo -n " -a $((i+S))"
	    done
	fi)

sed -i -f - "$livepatch_spec_file" <<EOF
s%@@KLP_PATCHES_SOURCES@@%$KLP_PATCHES_SOURCES%;
s,@@KLP_PATCHES_SETUP_SOURCES@@,$KLP_PATCHES_SETUP_SOURCES,;
EOF
