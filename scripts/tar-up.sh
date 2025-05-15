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
install -m 644 klp_syscalls.h $build_dir
install -m 644 klp_trace.h $build_dir
install -m 644 rpm/kernel-livepatch.spec $build_dir/kernel-livepatch-"$RELEASE".spec
scripts/register-patches.sh $build_dir/livepatch_main.c $build_dir/kernel-livepatch-"$RELEASE".spec
install -m 644 rpm/config.sh $build_dir/config.sh
install -m 755 scripts/lp-mod-checks.sh $build_dir/lp-mod-checks.sh

while read buildenv; do
	install -m 644 "$buildenv" "$build_dir/$(basename $buildenv)"
done < <(find rpm -maxdepth 1 -name '_buildenv.*')

# create new Makefile in $build_dir
scripts/create-makefile.sh $build_dir

# timestamp
tsfile=source-timestamp
ts=$(git show --pretty=format:%ct HEAD | head -n 1)
commit=$(git rev-parse HEAD)
date "+%Y-%m-%d %H:%M:%S %z" -d "1970-01-01 00:00 UTC $ts seconds" >$build_dir/$tsfile
echo "GIT Revision: $commit" >> $build_dir/$tsfile
branch=$(sed -ne 's|^ref: refs/heads/||p' .git/HEAD 2>/dev/null)
if test -n "$branch"; then
	echo "GIT Branch: $branch" >>$build_dir/$tsfile
fi

# ExclusiveArch and variant
variant=
excarch='x86_64'

if echo "$RELEASE" | \
	grep -q '^SLE\([0-9]\+\)\(-SP\([0-9]\+\)\)\?\(-[a-zA-Z_]\+\)\?_Update_\([0-9]\+\)$'; then
  # Break $RELEASE into array of SLE release, -SP, kernel variant
  # and -_Update number.

  cs=( \
    $(echo "$RELEASE" | \
      sed 's/SLE\([0-9]\+\)\(-SP\([0-9]\+\)\)\?\(-[a-zA-Z_]\+\)\?_Update_\([0-9]\+\)/\1,\3,\4,\5/' | \
      awk -F, '{ print $1 " " ($2 ? $2 : 0) " " ($3 != "" ? $3 : "xempty") " " $4 }') \
    )

  if [ ${cs[2]} = xempty ]; then
      # Variant being empty means the build is against the default kernel.
      excarch="$excarch ppc64le"

      # s390x shall be enabled from SLE12-SP4 update 13 onwards.
      # s390x is supported for SLE12-SP5 from update 3 onwards.
      # s390x is supported from SLE15-SP2 onwards.
      if [ ${cs[0]} -eq 12 -a ${cs[1]} -eq 4 -a ${cs[3]} -ge 13 -o \
	   ${cs[0]} -eq 12 -a ${cs[1]} -eq 5 -a ${cs[3]} -ge 3 -o \
	   ${cs[0]} -eq 15 -a ${cs[1]} -ge 2 ]; then
	  excarch="$excarch s390x"
      fi

  else
      variant="$(echo "${cs[2]}" | tr '[:upper:]' '[:lower:]')"
  fi
elif echo "$RELEASE" | \
	grep -q '^MICRO-\([0-9]\+\)-\([0-9]\+\)\(-[a-zA-Z_]\+\)\?_Update_\([0-9]\+\)$'; then
  # Break $RELEASE into array of MICRO release major, minor, kernel variant
  # and -_Update number.

  cs=( \
    $(echo "$RELEASE" | \
      sed 's/MICRO-\([0-9]\+\)-\([0-9]\+\)\(-[a-zA-Z_]\+\)\?_Update_\([0-9]\+\)/\1,\2,\3,\4/' | \
      awk -F, '{ print $1 " " ($2 ? $2 : 0) " " ($3 != "" ? $3 : "xempty") " " $4 }') \
    )

  if [ ${cs[2]} = xempty ]; then
      # For MICRO-6-0, default kernel variant, x86_64 and s390x are
      # enabled.
      excarch="$excarch s390x"
  else
      variant="$(echo "${cs[2]}" | tr '[:upper:]' '[:lower:]')"
  fi
fi

sed -i \
	-e "s/@@RELEASE@@/$RELEASE/g" \
	-e "/@@SOURCE_TIMESTAMP@@/ {
		e echo -n 'Source timestamp: '; cat $build_dir/$tsfile
		d
	}" \
	-e "s/@@VARIANT@@/$variant/" \
	-e "s/@@EXCARCH@@/$excarch/" \
	$build_dir/kernel-livepatch-"$RELEASE".spec

sed -i "s/@@GITREV@@/$commit/" $build_dir/livepatch_main.c

# changelog
changelog=$build_dir/kernel-livepatch-"$RELEASE".changes
scripts/gitlog2changes.pl HEAD -- > "$changelog"
