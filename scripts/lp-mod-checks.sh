#!/bin/sh
# SPDX-License-Identifier: GPL-2.0-or-later

# Checks whether livepatch module don't have any dependency on other modules
# or no relocation into __jump_table section.

obj=$1

IS_LP=$(/usr/sbin/modinfo $obj | grep '^livepatch:' | sed s'/^livepatch:[[:blank:]]*//')
if [ "x$IS_LP" != xY ]; then
	exit 0;
fi

DEPS=$(/usr/sbin/modinfo $obj | grep '^depends:' | sed 's/^depends:[[:blank:]]*//')
if [ -n "$DEPS" ]; then
	echo "error: dependency on livepatch $obj" >&2
	exit 1
fi

RELOC=$(/usr/bin/readelf -W -S $obj | grep -E '\.klp\..*__jump_table')
if [ -n "$RELOC" ]; then
	echo "error: .klp.*__jump_table section found in livepatch $obj" >&2
	exit 1
fi
