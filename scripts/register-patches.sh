#!/bin/bash

#
# register-patches.sh -- add subpatches to kernel live patch
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

# This script expects a kernel live subpatch to live in a subdirectory
# SUBPATCH and to provide a SUBPATCH/livepatch_SUBPATCH.h
# header.
#
# This header must provide declarations for
# - klp_patch_SUBPATCH_init()
# - klp_patch_SUBPATCH_cleanup()
#
# Furthermore, each subpatch must provide a SUBPATCH/patched_funcs.csv
# file with one line of the form
#   obj old_func(,sympos) newfun (cpp #if condition)
# for every to be patched symbol.
#
#
# Usage:
#   register-patches.sh livepatch_main.c kernel-livepatch.spec
#
# This will properly substitute a number of placeholders in-place.
#

livepatch_main_file="$1"
livepatch_spec_file="$2"


# Generate list of patches
declare -a livepatches
declare -a patched_funcs
for d in *; do
	[ -d "$d" ] || continue
	[ x"$d" = xrpm -o x"$d" = xscripts -o x"$d" = xuname_patch ] && continue
	[ -e "$d/livepatch_main.c" ] && continue  # this is some builddir

	if [ ! -f "$d/livepatch_${d}.h" ]; then
	    echo "error: $d/ doesn't have a $d/livepatch_${d}.h" 1>&2
	    exit 1
	fi

	if [ ! -f "$d/patched_funcs.csv" ]; then
	    echo "error: $d/ doesn't have a $d/patched_funcs.csv" 1>&2
	    exit 1
	fi

	livepatches[${#livepatches[@]}]=$(basename $d)
	patched_funcs[${#patched_funcs[@]}]=$(basename $d)/patched_funcs.csv
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
objs=
if [ ${#patched_funcs[@]} -gt 0 ]; then
    objs=$(sed 's/[[:blank:]].*//' "${patched_funcs[@]}" | \
	       grep -v '^$' | \
	       grep -v vmlinux | sort | uniq)
fi
objs="vmlinux $objs"

KLP_PATCHES_OBJS=$(
	echo -n "\t/* Auto expanded KLP_PATCHES_OBJS: */\n"
	for o in $objs; do
	    # First gather the #if conditions for that object.
	    # vmlinux gets always patched because of uname().
	    declare -a o_conds
	    o_conds=()
	    if [ x"$o" != xvmlinux ]; then
		for pf in "${patched_funcs[@]}"; do
		    while read _o oldfun newfun cond; do
			if [ -z "$_o" ]; then
			    continue
			elif [ -z "$newfun" ]; then
			    echo "error: invalid patched_funcs line: " \
				 "$_o $oldfun" 1>&2
			elif [ x"$_o" != x"$o" ]; then
			    continue
			fi

			if [ -z "$cond" ]; then
			    # unconditional
			    o_conds=()
			    break
			else
			    # Avoid adding duplicates
			    for o_c in "${o_conds[@]}"; do
				if [ x"$o_c" = x"$cond" ]; then
				    cond=
				    break
				fi
			    done
			    if [ -n "$cond" ]; then
				o_conds[${#o_conds[@]}]="$cond"
			    fi
			fi
		    done < "$pf"
		done
	    fi

	    # Emit the #if condition for the object, if any
	    if [ ${#o_conds[@]} -eq 1 ]; then
		echo -n "#if ${o_conds[0]}\n"
	    elif [ ${#o_conds[@]} -ne 0 ]; then
		echo -n "#if "
		i=0
		while [ $i -lt ${#o_conds[@]} ]; do
		    if [ $i -ne 0 ]; then
			echo -n ' || '
		    fi
		    echo -n "(${o_conds[$i]})"
		    i=$((i + 1))
		done
		unset i
		echo -n '\n'
	    fi

	    echo -n '\t{\n'
	    if [ x"$o" = xvmlinux ]; then
		echo -n '\t\t.name = NULL,\n'
	    else
		echo -n "\t\t.name = \"$o\",\n"
	    fi
	    echo -n '\t\t.funcs = (struct klp_func[]) {\n'

	    if [ x"$o" = xvmlinux ]; then
		echo -n '\t\t\t{\n'
		echo -n '\t\t\t  .old_name = __stringify(KLP_SYSCALL_SYM(newuname)),\n'
		echo -n '\t\t\t  .new_func = KLP_SYSCALL_SYM(klp_newuname),\n'
		echo -n '\t\t\t},\n'
		echo -n '#ifdef KLP_ARCH_HAS_SYSCALL_COMPAT_STUBS\n'
		echo -n '\t\t\t{\n'
		echo -n '\t\t\t  .old_name = __stringify(KLP_SYSCALL_COMPAT_STUB_SYM(newuname)),\n'
		echo -n '\t\t\t  .new_func = KLP_SYSCALL_COMPAT_STUB_SYM(klp_newuname),\n'
		echo -n '\t\t\t},\n'
		echo -n '#endif\n'
	    fi

	    last_cond=
	    for pf in "${patched_funcs[@]}"; do
		while read _o oldfun newfun cond; do
		    if [ -z "$_o" ]; then
			continue
		    elif [ -z "$newfun" ]; then
			echo "error: invalid patched_funcs line: " \
			     "$_o $oldfun" 1>&2
		    elif [ x"$_o" != x"$o" ]; then
			continue
		    fi

		    # Collate multiple subsequent klp_func entries
		    # guarded by the same #if condition. Also, do not
		    # emit #if pragmas at the klp_func level if it
		    # would be equivalent to what's already there at
		    # the enclosing object level.
		    if [ ${#o_conds[@]} -eq 1 -a x"${o_conds[0]}" = x"$cond" ]
		    then
			cond=
		    fi
		    if [ x"$last_cond" = x"$cond" ]; then
			cond=
		    else
			if [ -n "$last_cond" ]; then
			    echo -n "#endif\n"
			fi
			last_cond="$cond"
		    fi
		    if [ -n "$cond" ]; then
			echo -n "#if $cond\n"
		    fi

		    sympos=
		    if echo $oldfun | grep -q ','; then
			sympos=$(echo $oldfun | sed 's/[^,]\+,\(.\+\)/\1/')
			oldfun=$(echo $oldfun | sed 's/,.*//')
		    fi
		    echo -n "\t\t\t{ .old_name = \"$oldfun\", "
		    echo -n ".new_func = $newfun, "
		    if [ -n "$sympos" ]; then
			echo -n ".old_sympos = $sympos, "
		    fi
		    echo -n '},\n'
		done < "$pf"
	    done
	    if [ -n "$last_cond" ]; then
		echo -n "#endif\n"
	    fi
	    echo -n '\t\t\t{ }\n'
	    echo -n '\t\t}\n'
	    echo -n '\t},\n'
	    if [ ${#o_conds[@]} -ne 0 ]; then
		echo -n '#endif\n'
	    fi
	done
	printf '\t{ }\n'
)
### Escape the '&' character in the sed replacement
KLP_PATCHES_OBJS="$(echo -n "$KLP_PATCHES_OBJS" | sed 's/&/\\&/g')"

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
)

## Cleanup the individual patches in livepatch_cleanup().
KLP_PATCHES_CLEANUP_CALLS=$(
	echo -n "\t/* Auto expanded KLP_PATCHES_CLEANUP_CALLS: */\n"
	for p in "${livepatches[@]}"; do
		echo -n "\tlivepatch_${p}_cleanup();\n"
	done)

sed -i -f - "$livepatch_main_file" <<EOF
s%@@KLP_PATCHES_INCLUDES@@%$KLP_PATCHES_INCLUDES%;
s%\s*@@KLP_PATCHES_OBJS@@,\?%$KLP_PATCHES_OBJS%;
s%\s*@@KLP_PATCHES_INIT_CALLS@@;\?%$KLP_PATCHES_INIT_CALLS%;
s%\s*@@KLP_PATCHES_INIT_ERR_HANDLERS@@;\?%$KLP_PATCHES_INIT_ERR_HANDLERS%;
s%\s*@@KLP_PATCHES_CLEANUP_CALLS@@;\?%$KLP_PATCHES_CLEANUP_CALLS%;
s%\s*@@KLP_PATCHES_CLEANUP_CALLS@@;\?%$KLP_PATCHES_CLEANUP_CALLS%;
EOF

# Finish kernel-livepatch.spec:
## Enumerate the per subpatch source *.tar.bz2.
## Note: Start with Source10
S=10
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
