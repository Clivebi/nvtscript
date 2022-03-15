if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.704082" );
	script_version( "2021-06-18T11:51:03+0000" );
	script_cve_id( "CVE-2017-1000407", "CVE-2017-1000410", "CVE-2017-15868", "CVE-2017-16538", "CVE-2017-16939", "CVE-2017-17448", "CVE-2017-17449", "CVE-2017-17450", "CVE-2017-17558", "CVE-2017-17741", "CVE-2017-17805", "CVE-2017-17806", "CVE-2017-17807", "CVE-2017-5754", "CVE-2017-8824" );
	script_name( "Debian Security Advisory DSA 4082-1 (linux - security update)" );
	script_tag( name: "last_modification", value: "2021-06-18 11:51:03 +0000 (Fri, 18 Jun 2021)" );
	script_tag( name: "creation_date", value: "2018-01-09 00:00:00 +0100 (Tue, 09 Jan 2018)" );
	script_tag( name: "cvss_base", value: "7.2" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:L/Au:N/C:C/I:C/A:C" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-10-03 00:03:00 +0000 (Thu, 03 Oct 2019)" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	script_xref( name: "URL", value: "https://www.debian.org/security/2018/dsa-4082.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB8" );
	script_tag( name: "affected", value: "linux on Debian Linux" );
	script_tag( name: "solution", value: "For the oldstable distribution (jessie), these problems have been fixed
in version 3.16.51-3+deb8u1.

We recommend that you upgrade your linux packages." );
	script_xref( name: "URL", value: "https://security-tracker.debian.org/tracker/linux" );
	script_tag( name: "summary", value: "Several vulnerabilities have been discovered in the Linux kernel that
may lead to a privilege escalation, denial of service or information
leaks.

CVE-2017-5754
Multiple researchers have discovered a vulnerability in Intel
processors, enabling an attacker controlling an unprivileged
process to read memory from arbitrary addresses, including from
the kernel and all other processes running on the system.

This specific attack has been named Meltdown and is addressed in
the Linux kernel for the Intel x86-64 architecture by a patch set
named Kernel Page Table Isolation, enforcing a near complete
separation of the kernel and userspace address maps and preventing
the attack. This solution might have a performance impact, and can
be disabled at boot time by passing pti=off
to the kernel
command line.

Description truncated. Please see the references for more information." );
	script_tag( name: "vuldetect", value: "This check tests the installed software version using the apt package manager." );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(!isnull( res = isdpkgvuln( pkg: "linux-compiler-gcc-4.8-arm", ver: "3.16.51-3+deb8u1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-compiler-gcc-4.8-s390", ver: "3.16.51-3+deb8u1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-compiler-gcc-4.8-x86", ver: "3.16.51-3+deb8u1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-doc-3.16", ver: "3.16.51-3+deb8u1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-headers-3.16.0-4-4kc-malta", ver: "3.16.51-3+deb8u1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-headers-3.16.0-4-586", ver: "3.16.51-3+deb8u1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-headers-3.16.0-4-5kc-malta", ver: "3.16.51-3+deb8u1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-headers-3.16.0-4-686-pae", ver: "3.16.51-3+deb8u1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-headers-3.16.0-4-all", ver: "3.16.51-3+deb8u1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-headers-3.16.0-4-all-amd64", ver: "3.16.51-3+deb8u1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-headers-3.16.0-4-all-arm64", ver: "3.16.51-3+deb8u1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-headers-3.16.0-4-all-armel", ver: "3.16.51-3+deb8u1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-headers-3.16.0-4-all-armhf", ver: "3.16.51-3+deb8u1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-headers-3.16.0-4-all-i386", ver: "3.16.51-3+deb8u1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-headers-3.16.0-4-all-mips", ver: "3.16.51-3+deb8u1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-headers-3.16.0-4-all-mipsel", ver: "3.16.51-3+deb8u1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-headers-3.16.0-4-all-powerpc", ver: "3.16.51-3+deb8u1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-headers-3.16.0-4-all-ppc64el", ver: "3.16.51-3+deb8u1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-headers-3.16.0-4-all-s390x", ver: "3.16.51-3+deb8u1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-headers-3.16.0-4-amd64", ver: "3.16.51-3+deb8u1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-headers-3.16.0-4-arm64", ver: "3.16.51-3+deb8u1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-headers-3.16.0-4-armmp", ver: "3.16.51-3+deb8u1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-headers-3.16.0-4-armmp-lpae", ver: "3.16.51-3+deb8u1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-headers-3.16.0-4-common", ver: "3.16.51-3+deb8u1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-headers-3.16.0-4-ixp4xx", ver: "3.16.51-3+deb8u1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-headers-3.16.0-4-kirkwood", ver: "3.16.51-3+deb8u1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-headers-3.16.0-4-loongson-2e", ver: "3.16.51-3+deb8u1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-headers-3.16.0-4-loongson-2f", ver: "3.16.51-3+deb8u1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-headers-3.16.0-4-loongson-3", ver: "3.16.51-3+deb8u1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-headers-3.16.0-4-octeon", ver: "3.16.51-3+deb8u1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-headers-3.16.0-4-orion5x", ver: "3.16.51-3+deb8u1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-headers-3.16.0-4-powerpc", ver: "3.16.51-3+deb8u1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-headers-3.16.0-4-powerpc-smp", ver: "3.16.51-3+deb8u1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-headers-3.16.0-4-powerpc64", ver: "3.16.51-3+deb8u1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-headers-3.16.0-4-powerpc64le", ver: "3.16.51-3+deb8u1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-headers-3.16.0-4-r4k-ip22", ver: "3.16.51-3+deb8u1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-headers-3.16.0-4-r5k-ip32", ver: "3.16.51-3+deb8u1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-headers-3.16.0-4-s390x", ver: "3.16.51-3+deb8u1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-headers-3.16.0-4-sb1-bcm91250a", ver: "3.16.51-3+deb8u1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-headers-3.16.0-4-versatile", ver: "3.16.51-3+deb8u1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-headers-3.16.0-5-586", ver: "3.16.51-3+deb8u1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-headers-3.16.0-5-686-pae", ver: "3.16.51-3+deb8u1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-headers-3.16.0-5-all", ver: "3.16.51-3+deb8u1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-headers-3.16.0-5-all-amd64", ver: "3.16.51-3+deb8u1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-headers-3.16.0-5-all-arm64", ver: "3.16.51-3+deb8u1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-headers-3.16.0-5-all-armel", ver: "3.16.51-3+deb8u1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-headers-3.16.0-5-all-armhf", ver: "3.16.51-3+deb8u1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-headers-3.16.0-5-all-i386", ver: "3.16.51-3+deb8u1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-headers-3.16.0-5-all-powerpc", ver: "3.16.51-3+deb8u1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-headers-3.16.0-5-all-ppc64el", ver: "3.16.51-3+deb8u1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-headers-3.16.0-5-all-s390x", ver: "3.16.51-3+deb8u1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-headers-3.16.0-5-amd64", ver: "3.16.51-3+deb8u1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-headers-3.16.0-5-arm64", ver: "3.16.51-3+deb8u1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-headers-3.16.0-5-armmp", ver: "3.16.51-3+deb8u1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-headers-3.16.0-5-armmp-lpae", ver: "3.16.51-3+deb8u1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-headers-3.16.0-5-common", ver: "3.16.51-3+deb8u1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-headers-3.16.0-5-ixp4xx", ver: "3.16.51-3+deb8u1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-headers-3.16.0-5-kirkwood", ver: "3.16.51-3+deb8u1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-headers-3.16.0-5-orion5x", ver: "3.16.51-3+deb8u1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-headers-3.16.0-5-powerpc", ver: "3.16.51-3+deb8u1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-headers-3.16.0-5-powerpc-smp", ver: "3.16.51-3+deb8u1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-headers-3.16.0-5-powerpc64", ver: "3.16.51-3+deb8u1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-headers-3.16.0-5-powerpc64le", ver: "3.16.51-3+deb8u1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-headers-3.16.0-5-s390x", ver: "3.16.51-3+deb8u1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-headers-3.16.0-5-versatile", ver: "3.16.51-3+deb8u1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-image-3.16.0-4-4kc-malta", ver: "3.16.51-3+deb8u1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-image-3.16.0-4-586", ver: "3.16.51-3+deb8u1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-image-3.16.0-4-5kc-malta", ver: "3.16.51-3+deb8u1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-image-3.16.0-4-686-pae", ver: "3.16.51-3+deb8u1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-image-3.16.0-4-686-pae-dbg", ver: "3.16.51-3+deb8u1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-image-3.16.0-4-amd64", ver: "3.16.51-3+deb8u1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-image-3.16.0-4-amd64-dbg", ver: "3.16.51-3+deb8u1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-image-3.16.0-4-arm64", ver: "3.16.51-3+deb8u1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-image-3.16.0-4-arm64-dbg", ver: "3.16.51-3+deb8u1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-image-3.16.0-4-armmp", ver: "3.16.51-3+deb8u1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-image-3.16.0-4-armmp-lpae", ver: "3.16.51-3+deb8u1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-image-3.16.0-4-ixp4xx", ver: "3.16.51-3+deb8u1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-image-3.16.0-4-kirkwood", ver: "3.16.51-3+deb8u1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-image-3.16.0-4-loongson-2e", ver: "3.16.51-3+deb8u1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-image-3.16.0-4-loongson-2f", ver: "3.16.51-3+deb8u1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-image-3.16.0-4-loongson-3", ver: "3.16.51-3+deb8u1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-image-3.16.0-4-octeon", ver: "3.16.51-3+deb8u1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-image-3.16.0-4-orion5x", ver: "3.16.51-3+deb8u1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-image-3.16.0-4-powerpc", ver: "3.16.51-3+deb8u1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-image-3.16.0-4-powerpc-smp", ver: "3.16.51-3+deb8u1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-image-3.16.0-4-powerpc64", ver: "3.16.51-3+deb8u1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-image-3.16.0-4-powerpc64le", ver: "3.16.51-3+deb8u1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-image-3.16.0-4-r4k-ip22", ver: "3.16.51-3+deb8u1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-image-3.16.0-4-r5k-ip32", ver: "3.16.51-3+deb8u1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-image-3.16.0-4-s390x", ver: "3.16.51-3+deb8u1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-image-3.16.0-4-s390x-dbg", ver: "3.16.51-3+deb8u1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-image-3.16.0-4-sb1-bcm91250a", ver: "3.16.51-3+deb8u1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-image-3.16.0-4-versatile", ver: "3.16.51-3+deb8u1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-image-3.16.0-5-586", ver: "3.16.51-3+deb8u1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-image-3.16.0-5-686-pae", ver: "3.16.51-3+deb8u1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-image-3.16.0-5-686-pae-dbg", ver: "3.16.51-3+deb8u1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-image-3.16.0-5-amd64", ver: "3.16.51-3+deb8u1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-image-3.16.0-5-amd64-dbg", ver: "3.16.51-3+deb8u1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-image-3.16.0-5-arm64", ver: "3.16.51-3+deb8u1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-image-3.16.0-5-arm64-dbg", ver: "3.16.51-3+deb8u1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-image-3.16.0-5-armmp", ver: "3.16.51-3+deb8u1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-image-3.16.0-5-armmp-lpae", ver: "3.16.51-3+deb8u1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-image-3.16.0-5-ixp4xx", ver: "3.16.51-3+deb8u1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-image-3.16.0-5-kirkwood", ver: "3.16.51-3+deb8u1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-image-3.16.0-5-orion5x", ver: "3.16.51-3+deb8u1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-image-3.16.0-5-powerpc", ver: "3.16.51-3+deb8u1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-image-3.16.0-5-powerpc-smp", ver: "3.16.51-3+deb8u1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-image-3.16.0-5-powerpc64", ver: "3.16.51-3+deb8u1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-image-3.16.0-5-powerpc64le", ver: "3.16.51-3+deb8u1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-image-3.16.0-5-s390x", ver: "3.16.51-3+deb8u1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-image-3.16.0-5-s390x-dbg", ver: "3.16.51-3+deb8u1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-image-3.16.0-5-versatile", ver: "3.16.51-3+deb8u1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-libc-dev", ver: "3.16.51-3+deb8u1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-manual-3.16", ver: "3.16.51-3+deb8u1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-source-3.16", ver: "3.16.51-3+deb8u1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-support-3.16.0-4", ver: "3.16.51-3+deb8u1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-support-3.16.0-5", ver: "3.16.51-3+deb8u1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "xen-linux-system-3.16.0-4-amd64", ver: "3.16.51-3+deb8u1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "xen-linux-system-3.16.0-5-amd64", ver: "3.16.51-3+deb8u1", rls: "DEB8" ) )){
	report += res;
}
if( report != "" ){
	security_message( data: report );
}
else {
	if(__pkg_match){
		exit( 99 );
	}
}

