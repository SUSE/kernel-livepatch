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
%define with_klp_info 1

Name:           kernel-livepatch-@@RELEASE@@
Version:        6
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
# Use kernel-<flavor> specific build dependencies instead of kernel-syms (bsc#1248108)
%if "%variant" != ""
BuildRequires:  kernel%variant-devel
%else
BuildRequires:  kernel-default-devel
%endif
BuildRequires:  pesign-obs-integration
BuildRequires:  kernel-livepatch-tools-devel
BuildRequires:  libelf-devel
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

mkdir -p "obj/%flavor"
cp -r "$@" "obj/%flavor"
make -C %{kernel_source %flavor} M="$PWD/obj/%flavor" modules

for module in $(find "obj/%flavor" -name '*.ko'); do
    /bin/sh %_sourcedir/lp-mod-checks.sh "$module"

    # Generate klp info cache when supported.
    touch info.list
    if test -n "%{?klp_package_name}" ; then
	MODNAME=$(/usr/sbin/modinfo -F name "$module")
	MODSRCVERSION=$(/usr/sbin/modinfo -F srcversion "$module")
	klp rpm_changes_to_klp_info %{_sourcedir}/%{name}.changes \
	    %{klp_package_name}-%{version}-%{release}.%{_arch} \
	    ${MODNAME}-${MODSRCVERSION}
	echo "${MODNAME}-${MODSRCVERSION}" >>info.list
    fi
done

%install
export INSTALL_MOD_DIR=livepatch
export INSTALL_MOD_PATH=%buildroot

make -C %{kernel_source %flavor} M="$PWD/obj/%flavor" modules_install

# Install klp info cache when any.
for info in $(cat info.list) ; do
    install -D -m0644 "$info" %{buildroot}/%{_datadir}/livepatch/info/"$info"
done

%changelog

