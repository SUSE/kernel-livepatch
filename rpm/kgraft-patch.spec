#
# spec file for package kGraft patch module
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

Name:           kgraft-patch-@@RELEASE@@
Version:        1
Release:        1
%define module_num %(echo %version-%release | sed 'y/\./_/')
License:        GPL-2.0
Summary:        Kgraft patch module
Group:          System/Kernel
Source0:	uname_patch.tar.bz2
Source1:	Makefile
Source2:        kgr_patch_main.c
Source3:        config.sh
Source4:        source-timestamp
@@KGR_PATCHES_SOURCES@@
BuildRequires:  kernel-syms kgraft-devel
ExclusiveArch:	@@EXCARCH@@
%kgraft_module_package

%description
This is a live patch for SUSE Linux Enterprise Server kernel.

@@SOURCE_TIMESTAMP@@

%prep
%setup -c
@@KGR_PATCHES_SETUP_SOURCES@@
cp %_sourcedir/kgr_patch_main.c .
cp %_sourcedir/Makefile .

%build
sed -i 's/@@RPMRELEASE@@/%module_num/g' Makefile
sed -i 's/@@RPMRELEASE@@/%module_num/g' kgr_patch_main.c
echo 'kgraft-patch-%module_num' >Module.supported
set -- *

commit=$(sed -n 's/GIT Revision: //p' %_sourcedir/source-timestamp)
sed -i "s/@@GITREV@@/${commit:0:7}/g" uname_patch/kgr_patch_uname.c

for flavor in %flavors_to_build; do
	mkdir -p "obj/$flavor"
	cp -r "$@" "obj/$flavor"
	make -C %{kernel_source $flavor} M="$PWD/obj/$flavor" modules
done

%install
export INSTALL_MOD_DIR=kgraft
export INSTALL_MOD_PATH=%buildroot
for flavor in %flavors_to_build; do
	make -C %{kernel_source $flavor} M="$PWD/obj/$flavor" modules_install
done

%changelog

