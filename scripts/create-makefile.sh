#!/bin/sh

# Automatically generate a Makefile
# $1 is output directory

if [ -e "$1/Makefile" ]; then
	echo "Makefile already exists."
	exit 0
fi

objects=$(find . -type f -name "*.c" -o -iname "*.s" | sed "s/^\.\/\(.*\)\.[csS]$/\1.o/" | tr '\n' ' ')

cat << EOF > $1/Makefile
KDIR ?= /lib/modules/\`uname -r\`/build

ccflags-y += -I\$(obj)

obj-m := livepatch-@@RPMRELEASE@@.o

livepatch-@@RPMRELEASE@@-y := $objects

default:
	\$(MAKE) -C \$(KDIR) M=\$(CURDIR) modules

clean:
	\$(MAKE) -C \$(KDIR) M=\$(CURDIR) clean
EOF
