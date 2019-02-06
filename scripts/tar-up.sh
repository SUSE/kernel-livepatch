#
# tar-up.sh - script for building a kernel live patch rpm package
#
# Copyright (c) 2014 SUSE
#  Author: Miroslav Benes <mbenes@suse.cz>
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

#!/bin/bash

# options
until [ "$#" = "0" ] ; do
  case "$1" in
    --dir=*)
      build_dir=${1#*=}
      shift
      ;;
    -d|--dir)
      build_dir=$2
      shift 2
      ;;
    -h|--help|-v|--version)
	cat <<EOF

${0##*/} prepares a kernel live patch module package for submission into build service

these options are recognized:
    -d, --dir=DIR      create package in DIR instead of default klp-mod-source

EOF
	exit 1
	;;
    *)
      echo "unknown option '$1'" >&2
      exit 1
      ;;
  esac
done

# builddir
[ -z "$build_dir" ] && build_dir=klp-mod-source
if [ -z "$build_dir" ]; then
    echo "Please define the build directory with the --dir option" >&2
    exit 1
fi

rm -f "$build_dir"/*
mkdir -p "$build_dir"

# archives
# pack all directories with live patches
#	rpm/, scripts/ and $build_dir (if local) are excluded
build_dir_trim=$(basename $build_dir)
archives=$(ls -d */ | cut -f1 -d'/' | sed -r "s/rpm|scripts|$build_dir_trim//")
for archive in $archives; do
	echo "$archive.tar.bz2"
	tar cfj $build_dir/$archive.tar.bz2 $archive
done

# install to builddir
source $(dirname $0)/release-version.sh

install -m 644 livepatch_main.c $build_dir
install -m 644 shadow.h $build_dir
install -m 644 kallsyms_relocs.h $build_dir
install -m 644 kallsyms_relocs.c $build_dir
install -m 644 klp_convert.h $build_dir
install -m 644 rpm/kernel-livepatch.spec $build_dir/kernel-livepatch-"$RELEASE".spec
scripts/register-patches.sh $build_dir/livepatch_main.c $build_dir/kernel-livepatch-"$RELEASE".spec
install -m 644 rpm/config.sh $build_dir/config.sh

# create new Makefile in $build_dir
scripts/create-makefile.sh $build_dir

# timestamp
tsfile=source-timestamp
ts=$(git show --pretty=format:%ct HEAD | head -n 1)
date "+%Y-%m-%d %H:%M:%S %z" -d "1970-01-01 00:00 UTC $ts seconds" >$build_dir/$tsfile
echo "GIT Revision: $(git rev-parse HEAD)" >> $build_dir/$tsfile
branch=$(sed -ne 's|^ref: refs/heads/||p' .git/HEAD 2>/dev/null)
if test -n "$branch"; then
	echo "GIT Branch: $branch" >>$build_dir/$tsfile
fi

sed -i \
	-e "s/@@RELEASE@@/$RELEASE/g" \
	-e "/@@SOURCE_TIMESTAMP@@/ {
		e echo -n 'Source timestamp: '; cat $build_dir/$tsfile
		d
	}" \
	$build_dir/kernel-livepatch-"$RELEASE".spec

# changelog
changelog=$build_dir/kernel-livepatch-"$RELEASE".changes
scripts/gitlog2changes.pl HEAD -- > "$changelog"

# klp-convert
parse_release() {
	echo "$1" | \
		sed 's/SLE\([0-9]\+\)\(-SP\([0-9]\+\)\)\?_Update_\([0-9]\+\)/\1,\3,\4/' | \
		awk -F, '{ print $1 " " ($2 ? $2 : 0) " " $3 }'
}

rel=($(parse_release $RELEASE))
if [[ -n "${rel[0]##*Test*}" && ${rel[0]} -eq 15 && ${rel[1]} -eq 1 ]]; then
	sed -i "s/@@USE_KLP_CONVERT@@/%define use_klp_convert 1/" $build_dir/kernel-livepatch-"$RELEASE".spec
	sed -i "/^KDIR/a ccflags-y := -DUSE_KLP_CONVERT" $build_dir/Makefile
else
	sed -i "s/@@USE_KLP_CONVERT@@//" $build_dir/kernel-livepatch-"$RELEASE".spec
fi
