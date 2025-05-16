#
# spec file for package Kernel live patch module
#
# Copyright (c) 2014 SUSE LINUX Products GmbH, Nuernberg, Germany.
#
# All modifications and additions to the file contributed by third parties
# remain the property of their copyright owners, unless otherwise agreed
# upon. The license for this file, and modifications and additions to the
# file, is the same license as for the pristine package itself (unless the
# license for the pristine package is not an Open Source License, in which
# case the license is the MIT License). An "Open Source License" is a
# license that conforms to the Open Source Definition (Version 1.9)
# published by the Open Source Initiative.

# Please submit bugfixes or comments via http://bugs.opensuse.org/
#

# needssslcertforbuild

%define variant @@VARIANT@@%{nil}

Name:           kernel-livepatch-@@RELEASE@@
Version:        14
Release:        1
%define module_num %(echo %version-%release | sed 'y/\./_/')
License:        GPL-2.0
Summary:        Kernel live patch module
Group:          System/Kernel
Source0:	uname_patch.tar.bz2
Source1:	Makefile
Source2:        livepatch_main.c
Source3:        config.sh
Source4:        source-timestamp
Source5:        shadow.h
Source6:	klp_syscalls.h
Source7:	klp_trace.h
Source8:	lp-mod-checks.sh
@@KLP_PATCHES_SOURCES@@
BuildRequires:  kernel-syms%{variant} kernel-livepatch-tools-devel libelf-devel
ExclusiveArch:	@@EXCARCH@@
%klp_module_package

%description
This is a live patch for SUSE Linux Enterprise Server kernel.

@@SOURCE_TIMESTAMP@@

%prep
%setup -c
@@KLP_PATCHES_SETUP_SOURCES@@
cp %_sourcedir/livepatch_main.c .
cp %_sourcedir/shadow.h .
cp %_sourcedir/Makefile .
cp %_sourcedir/klp_syscalls.h .
cp %_sourcedir/klp_trace.h .

%build
sed -i 's/@@RPMRELEASE@@/%module_num/g' Makefile
sed -i 's/@@RPMRELEASE@@/%module_num/g' livepatch_main.c
echo 'livepatch-%module_num' >Module.supported
set -- *

for flavor in %flavors_to_build; do
	mkdir -p "obj/$flavor"
	cp -r "$@" "obj/$flavor"
	make -C %{kernel_source $flavor} M="$PWD/obj/$flavor" modules

	for module in $(find "obj/$flavor" -name '*.ko'); do
	    /bin/sh %_sourcedir/lp-mod-checks.sh "$module"
	done
done

%install
export INSTALL_MOD_DIR=livepatch
export INSTALL_MOD_PATH=%buildroot
for flavor in %flavors_to_build; do
	make -C %{kernel_source $flavor} M="$PWD/obj/$flavor" modules_install
done

%changelog

