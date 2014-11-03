#!/bin/bash

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

${0##*/} prepares a kGraft module package for submission into build service

these options are recognized:
    -d, --dir=DIR      create package in DIR instead of default kgraft-mod-source

EOF
	exit 1
	;;
    *)
      echo "unknown option '$1'" >&2
      exit 1
      ;;
  esac
done

[ -z "$build_dir" ] && build_dir=kgraft-mod-source
if [ -z "$build_dir" ]; then
    echo "Please define the build directory with the --dir option" >&2
    exit 1
fi

rm -f "$build_dir"/*
mkdir -p "$build_dir"

# eventual TODO: make it more general
archives="uname_patch"
for archive in $archives; do
	echo "$archive.tar.bz2"
	tar cfj $build_dir/$archive.tar.bz2 $archive
done

source $(dirname $0)/release-version.sh

install -m 644 kgr_patch_main.c $build_dir
install -m 644 Makefile $build_dir
install -m 644 rpm/kgraft-patch.spec $build_dir/kgraft-patch-"$RELEASE".spec
install -m 644 rpm/kgraft-patch.changes $build_dir/kgraft-patch-"$RELEASE".changes

sed -i "s/@@RELEASE@@/$RELEASE/g" $build_dir/kgr_patch_main.c \
	 $build_dir/kgraft-patch-"$RELEASE".spec
