Summary: SELinux binary policy manipulation library 
Name: libsepol
Version: 1.4
Release: 1
License: GPL
Group: System Environment/Libraries
Source: http://www.nsa.gov/selinux/archives/%{name}-%{version}.tgz
Prefix: %{_prefix}
BuildRoot: %{_tmppath}/%{name}-buildroot
Provides: libsepol.so

%description
Security-enhanced Linux is a patch of the Linux® kernel and a number
of utilities with enhanced security functionality designed to add
mandatory access controls to Linux.  The Security-enhanced Linux
kernel contains new architectural components originally developed to
improve the security of the Flask operating system. These
architectural components provide general support for the enforcement
of many kinds of mandatory access control policies, including those
based on the concepts of Type Enforcement®, Role-based Access
Control, and Multi-level Security.

libsepol provides an API for the manipulation of SELinux binary policies.
It is used by checkpolicy (the policy compiler) and similar tools, as well
as by programs like load_policy that need to perform specific transformations
on binary policies such as customizing policy boolean settings.

%package devel
Summary: Header files and libraries used to build policy manipulation tools
Group: Development/Libraries
Requires: libsepol = %{version}

%description devel
The sepol-devel package contains the static libraries and header files
needed for developing applications that manipulate binary policies. 

%prep
%setup -q

%build
make CFLAGS="%{optflags}"

%install
rm -rf ${RPM_BUILD_ROOT}
mkdir -p ${RPM_BUILD_ROOT}/%{_lib} 
mkdir -p ${RPM_BUILD_ROOT}/%{_libdir} 
mkdir -p ${RPM_BUILD_ROOT}%{_includedir} 
mkdir -p ${RPM_BUILD_ROOT}%{_bindir} 
mkdir -p ${RPM_BUILD_ROOT}%{_mandir}/man3
mkdir -p ${RPM_BUILD_ROOT}%{_mandir}/man8
make DESTDIR="${RPM_BUILD_ROOT}" LIBDIR="${RPM_BUILD_ROOT}%{_libdir}" SHLIBDIR="${RPM_BUILD_ROOT}/%{_lib}" install

%clean
rm -rf ${RPM_BUILD_ROOT}

%post -p /sbin/ldconfig

%postun -p /sbin/ldconfig

%files devel
%defattr(-,root,root)
%{_libdir}/libsepol.a
%{_libdir}/libsepol.so
%{_includedir}/sepol/*.h
%{_mandir}/man3/*.3.gz
%{_bindir}/*
%{_mandir}/man8/*.8.gz

%files
%defattr(-,root,root)
/%{_lib}/libsepol.so.1

%changelog
