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

@@USE_KLP_CONVERT@@

Name:           kgraft-patch-@@RELEASE@@
Version:        7
Release:        1
%define module_num %(echo %version-%release | sed 'y/\./_/')
License:        GPL-2.0
Summary:        Kgraft patch module
Group:          System/Kernel
Source0:	uname_patch.tar.bz2
Source1:	Makefile
Source2:        livepatch_main.c
Source3:        config.sh
Source4:        source-timestamp
Source5:        shadow.h
Source6:        kallsyms_relocs.h
Source7:        kallsyms_relocs.c
Source8:	klp_convert.h
Source9:	klp_syscalls.h
@@KLP_PATCHES_SOURCES@@
BuildRequires:  kernel-syms kgraft-devel libelf-devel
%if 0%{?use_klp_convert}
BuildRequires:  kernel-default-kgraft-devel
%endif
ExclusiveArch:	@@EXCARCH@@
%kgraft_module_package

%description
This is a live patch for SUSE Linux Enterprise Server kernel.

@@SOURCE_TIMESTAMP@@

%prep
%setup -c
@@KLP_PATCHES_SETUP_SOURCES@@
cp %_sourcedir/livepatch_main.c .
cp %_sourcedir/shadow.h .
cp %_sourcedir/kallsyms_relocs.h .
cp %_sourcedir/kallsyms_relocs.c .
cp %_sourcedir/Makefile .
cp %_sourcedir/klp_convert.h .
cp %_sourcedir/klp_syscalls.h .

%build
sed -i 's/@@RPMRELEASE@@/%module_num/g' Makefile
sed -i 's/@@RPMRELEASE@@/%module_num/g' livepatch_main.c
echo 'kgraft-patch-%module_num' >Module.supported
set -- *

commit=$(sed -n 's/GIT Revision: //p' %_sourcedir/source-timestamp)
sed -i "s/@@GITREV@@/${commit:0:7}/g" uname_patch/livepatch_uname.c

for flavor in %flavors_to_build; do
	mkdir -p "obj/$flavor"
	cp -r "$@" "obj/$flavor"
	make -C %{kernel_source $flavor} M="$PWD/obj/$flavor" modules

	%if 0%{?use_klp_convert}
		module=$(find "obj/$flavor" -name 'kgraft[-_]patch*.ko' -printf '%f')
		klp-convert /usr/src/linux-obj/%_target_cpu/$flavor/Symbols.list \
			obj/$flavor/$module obj/$flavor/${module}_converted
		mv obj/$flavor/${module}_converted obj/$flavor/$module
	%endif
done

%install
export INSTALL_MOD_DIR=kgraft
export INSTALL_MOD_PATH=%buildroot
for flavor in %flavors_to_build; do
	make -C %{kernel_source $flavor} M="$PWD/obj/$flavor" modules_install
done

%changelog

