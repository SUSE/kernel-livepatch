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
# SUBPATCH and to provide a SUBPATCH/kgr_patch_SUBPATCH.h
# header.
#
# This header must provide declarations for
# - kgr_patch_SUBPATCH_init()
# - kgr_patch_SUBPATCH_cleanup()
# and an (all uppercase) KGR_PATCH_SUBPATCH_FUNCS macro.
# The latter should be a comma separated list of KGR_PATCH*() entries,
# each corresponding to a function the subpatch wants to replace.
#
# Usage:
#   register-patches.sh kgr_patch_main.c kgraft-patch.spec
#
# This will properly substitute a number of placeholders in-place.
#

kgr_patch_main_file="$1"
kgr_patch_spec_file="$2"


# Generate list of patches
declare -a kgr_patches
for d in *; do
	[ -d "$d" ] || continue
	[ x"$d" = xrpm -o x"$d" = xscripts -o x"$d" = xuname_patch ] && continue
	[ -e "$d/kgr_patch_main.c" ] && continue  # this is some builddir

	if [ ! -f "$d/kgr_patch_${d}.h" ]; then
	    echo "error: $d/ doesn't have a $d/kgr_patch_${d}.h" 1>&2
	    exit 1
	fi

	kgr_patches[${#kgr_patches[@]}]=$(basename $d)
done

# Sort it
kgr_patches=($(
	for p in "${kgr_patches[@]}"; do
		echo $p
	done | sort))


# Finish kgr_patch_main.c:
## Add includes of per-patch headers.
KGR_PATCHES_INCLUDES=$(
	echo -n "/* Auto expanded KGR_PATCHES_INCLUDES: */\n"
	for p in "${kgr_patches[@]}"; do
		echo -n "#include \"${p}/kgr_patch_${p}.h\"\n"
	done)

## Add the individual patches' replacement entries to struct kgr_patch.
KGR_PATCHES_FUNCS=$(
	echo -n "\t\t/* Auto expanded KGR_PATCHES_FUNCS: */\n"
	for p in "${kgr_patches[@]}"; do
		p="KGR_PATCH_$(echo $p | tr '[:lower:]' '[:upper:]')_FUNCS"
		echo -n "\t\t${p}\n"
	done | sed 's/\\n$//' # rm trailing extra newlines
)

## Initialize the individual patches in kgr_patch_init().
KGR_PATCHES_INIT_CALLS=$(
	echo -n "\t/* Auto expanded KGR_PATCHES_INIT_CALLS: */\n"
	for p in "${kgr_patches[@]}"; do
		cat <<EOF
	retval = kgr_patch_${p}_init();
	if (retval)
		goto err_${p};

EOF
	done | sed 's%\t%\\t%g' | sed 's%$%\\n%g' | tr -d '\n' \
		    | sed 's/\(\\n\)\?\\n$//' # rm trailing extra newlines
)

## Setup the rollback error handlers in kgr_patch_init().
KGR_PATCHES_INIT_ERR_HANDLERS=$(
	echo -n "\t/* Auto expanded KGR_PATCHES_INIT_ERR_HANDLERS: */\n"
	for i in $(seq $((${#kgr_patches[@]} - 1)) -1 0); do
	    cat <<EOF
	kgr_patch_${kgr_patches[$i]}_cleanup();
err_${kgr_patches[$i]}:
EOF
	done | sed 's%\t%\\t%g' | sed 's%$%\\n%g' | tr -d '\n';
	echo "\treturn retval;"
)

## Cleanup the individual patches in kgr_patch_cleanup().
KGR_PATCHES_CLEANUP_CALLS=$(
	echo -n "\t/* Auto expanded KGR_PATCHES_CLEANUP_CALLS: */\n"
	for p in "${kgr_patches[@]}"; do
		echo -n "\tkgr_patch_${p}_cleanup();\n"
	done)

sed -i -f - "$kgr_patch_main_file" <<EOF
s%@@KGR_PATCHES_INCLUDES@@%$KGR_PATCHES_INCLUDES%;
s%\s*@@KGR_PATCHES_FUNCS@@,\?%$KGR_PATCHES_FUNCS%;
s%\s*@@KGR_PATCHES_INIT_CALLS@@;\?%$KGR_PATCHES_INIT_CALLS%;
s%\s*@@KGR_PATCHES_INIT_ERR_HANDLERS@@:\?%$KGR_PATCHES_INIT_ERR_HANDLERS%;
s%\s*@@KGR_PATCHES_CLEANUP_CALLS@@;\?%$KGR_PATCHES_CLEANUP_CALLS%;
s%\s*@@KGR_PATCHES_CLEANUP_CALLS@@;\?%$KGR_PATCHES_CLEANUP_CALLS%;
EOF


# Finish kgraft-patch.spec:
## Enumerate the per subpatch source *.tar.bz2.
## Note: Start with Source6
S=6
## First check that none of the to be occupied Source<n> slots has
## been used already.
for i in "${!kgr_patches[@]}"; do
    if grep -q "^\s*Source$((i+S))\s*:" "$kgr_patch_spec_file"; then
	echo "error: Source$((i+S)) already used in $kgr_patch_spec_file" 1>&2
	exit 1;
    fi
done

KGR_PATCHES_SOURCES=$(
	echo -n "# Auto expanded KGR_PATCHES_SOURCES:\n"
	for i in "${!kgr_patches[@]}"; do
		echo -n "Source$((i+S)):\t${kgr_patches[i]}.tar.bz2\n"
	done | sed 's/\\n$//' # rm trailing extra newlines
)

## And extract them from %prep
KGR_PATCHES_SETUP_SOURCES=$(
	echo -n "# Auto expanded KGR_PATCHES_SETUP_SOURCES:\n"
	if [ ${#kgr_patches[@]} -gt 0 ]; then
	    echo -n '%setup -T -D'
	    for i in "${!kgr_patches[@]}"; do
		echo -n " -a $((i+S))"
	    done
	fi)

sed -i -f - "$kgr_patch_spec_file" <<EOF
s%@@KGR_PATCHES_SOURCES@@%$KGR_PATCHES_SOURCES%;
s,@@KGR_PATCHES_SETUP_SOURCES@@,$KGR_PATCHES_SETUP_SOURCES,;
EOF
