if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.704073" );
	script_version( "2021-09-14T09:01:51+0000" );
	script_cve_id( "CVE-2017-1000407", "CVE-2017-1000410", "CVE-2017-16538", "CVE-2017-16644", "CVE-2017-16995", "CVE-2017-17448", "CVE-2017-17449", "CVE-2017-17450", "CVE-2017-17558", "CVE-2017-17712", "CVE-2017-17741", "CVE-2017-17805", "CVE-2017-17806", "CVE-2017-17807", "CVE-2017-17862", "CVE-2017-17863", "CVE-2017-17864", "CVE-2017-8824" );
	script_name( "Debian Security Advisory DSA 4073-1 (linux - security update)" );
	script_tag( name: "last_modification", value: "2021-09-14 09:01:51 +0000 (Tue, 14 Sep 2021)" );
	script_tag( name: "creation_date", value: "2017-12-23 00:00:00 +0100 (Sat, 23 Dec 2017)" );
	script_tag( name: "cvss_base", value: "7.2" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:L/Au:N/C:C/I:C/A:C" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:P/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2018-08-24 10:29:00 +0000 (Fri, 24 Aug 2018)" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	script_xref( name: "URL", value: "https://www.debian.org/security/2017/dsa-4073.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2017 Greenbone Networks GmbH" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB9" );
	script_tag( name: "affected", value: "linux on Debian Linux" );
	script_tag( name: "solution", value: "For the stable distribution (stretch), these problems have been fixed in
version 4.9.65-3+deb9u1.

We recommend that you upgrade your linux packages." );
	script_xref( name: "URL", value: "https://security-tracker.debian.org/tracker/linux" );
	script_tag( name: "summary", value: "Several vulnerabilities have been discovered in the Linux kernel that
may lead to a privilege escalation, denial of service or information
leaks.

CVE-2017-8824Mohamed Ghannam discovered that the DCCP implementation did not
correctly manage resources when a socket is disconnected and
reconnected, potentially leading to a use-after-free. A local
user could use this for denial of service (crash or data
corruption) or possibly for privilege escalation. On systems that
do not already have the dccp module loaded, this can be mitigated
by disabling it:
echo>> /etc/modprobe.d/disable-dccp.conf install dccp falseCVE-2017-16538
Andrey Konovalov reported that the dvb-usb-lmedm04 media driver
did not correctly handle some error conditions during
initialisation. A physically present user with a specially
designed USB device can use this to cause a denial of service
(crash).

Description truncated. Please see the references for more information." );
	script_tag( name: "vuldetect", value: "This check tests the installed software version using the apt package manager." );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(!isnull( res = isdpkgvuln( pkg: "hyperv-daemons", ver: "4.9.65-3+deb9u1", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libcpupower-dev", ver: "4.9.65-3+deb9u1", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libcpupower1", ver: "4.9.65-3+deb9u1", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libusbip-dev", ver: "4.9.65-3+deb9u1", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-compiler-gcc-6-arm", ver: "4.9.65-3+deb9u1", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-compiler-gcc-6-s390", ver: "4.9.65-3+deb9u1", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-compiler-gcc-6-x86", ver: "4.9.65-3+deb9u1", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-cpupower", ver: "4.9.65-3+deb9u1", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-doc-4.9", ver: "4.9.65-3+deb9u1", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-headers-4.9.0-3-4kc-malta", ver: "4.9.65-3+deb9u1", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-headers-4.9.0-3-5kc-malta", ver: "4.9.65-3+deb9u1", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-headers-4.9.0-3-686", ver: "4.9.65-3+deb9u1", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-headers-4.9.0-3-686-pae", ver: "4.9.65-3+deb9u1", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-headers-4.9.0-3-all", ver: "4.9.65-3+deb9u1", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-headers-4.9.0-3-all-amd64", ver: "4.9.65-3+deb9u1", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-headers-4.9.0-3-all-arm64", ver: "4.9.65-3+deb9u1", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-headers-4.9.0-3-all-armel", ver: "4.9.65-3+deb9u1", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-headers-4.9.0-3-all-armhf", ver: "4.9.65-3+deb9u1", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-headers-4.9.0-3-all-i386", ver: "4.9.65-3+deb9u1", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-headers-4.9.0-3-all-mips", ver: "4.9.65-3+deb9u1", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-headers-4.9.0-3-all-mips64el", ver: "4.9.65-3+deb9u1", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-headers-4.9.0-3-all-mipsel", ver: "4.9.65-3+deb9u1", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-headers-4.9.0-3-all-ppc64el", ver: "4.9.65-3+deb9u1", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-headers-4.9.0-3-all-s390x", ver: "4.9.65-3+deb9u1", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-headers-4.9.0-3-amd64", ver: "4.9.65-3+deb9u1", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-headers-4.9.0-3-arm64", ver: "4.9.65-3+deb9u1", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-headers-4.9.0-3-armmp", ver: "4.9.65-3+deb9u1", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-headers-4.9.0-3-armmp-lpae", ver: "4.9.65-3+deb9u1", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-headers-4.9.0-3-common", ver: "4.9.65-3+deb9u1", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-headers-4.9.0-3-common-rt", ver: "4.9.65-3+deb9u1", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-headers-4.9.0-3-loongson-3", ver: "4.9.65-3+deb9u1", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-headers-4.9.0-3-marvell", ver: "4.9.65-3+deb9u1", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-headers-4.9.0-3-octeon", ver: "4.9.65-3+deb9u1", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-headers-4.9.0-3-powerpc64le", ver: "4.9.65-3+deb9u1", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-headers-4.9.0-3-rt-686-pae", ver: "4.9.65-3+deb9u1", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-headers-4.9.0-3-rt-amd64", ver: "4.9.65-3+deb9u1", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-headers-4.9.0-3-s390x", ver: "4.9.65-3+deb9u1", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-headers-4.9.0-4-4kc-malta", ver: "4.9.65-3+deb9u1", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-headers-4.9.0-4-5kc-malta", ver: "4.9.65-3+deb9u1", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-headers-4.9.0-4-686", ver: "4.9.65-3+deb9u1", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-headers-4.9.0-4-686-pae", ver: "4.9.65-3+deb9u1", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-headers-4.9.0-4-all", ver: "4.9.65-3+deb9u1", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-headers-4.9.0-4-all-amd64", ver: "4.9.65-3+deb9u1", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-headers-4.9.0-4-all-arm64", ver: "4.9.65-3+deb9u1", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-headers-4.9.0-4-all-armel", ver: "4.9.65-3+deb9u1", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-headers-4.9.0-4-all-armhf", ver: "4.9.65-3+deb9u1", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-headers-4.9.0-4-all-i386", ver: "4.9.65-3+deb9u1", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-headers-4.9.0-4-all-mips", ver: "4.9.65-3+deb9u1", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-headers-4.9.0-4-all-mips64el", ver: "4.9.65-3+deb9u1", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-headers-4.9.0-4-all-mipsel", ver: "4.9.65-3+deb9u1", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-headers-4.9.0-4-all-ppc64el", ver: "4.9.65-3+deb9u1", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-headers-4.9.0-4-all-s390x", ver: "4.9.65-3+deb9u1", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-headers-4.9.0-4-amd64", ver: "4.9.65-3+deb9u1", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-headers-4.9.0-4-arm64", ver: "4.9.65-3+deb9u1", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-headers-4.9.0-4-armmp", ver: "4.9.65-3+deb9u1", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-headers-4.9.0-4-armmp-lpae", ver: "4.9.65-3+deb9u1", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-headers-4.9.0-4-common", ver: "4.9.65-3+deb9u1", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-headers-4.9.0-4-common-rt", ver: "4.9.65-3+deb9u1", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-headers-4.9.0-4-loongson-3", ver: "4.9.65-3+deb9u1", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-headers-4.9.0-4-marvell", ver: "4.9.65-3+deb9u1", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-headers-4.9.0-4-octeon", ver: "4.9.65-3+deb9u1", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-headers-4.9.0-4-powerpc64le", ver: "4.9.65-3+deb9u1", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-headers-4.9.0-4-rt-686-pae", ver: "4.9.65-3+deb9u1", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-headers-4.9.0-4-rt-amd64", ver: "4.9.65-3+deb9u1", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-headers-4.9.0-4-s390x", ver: "4.9.65-3+deb9u1", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-image-4.9.0-3-4kc-malta", ver: "4.9.65-3+deb9u1", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-image-4.9.0-3-4kc-malta-dbg", ver: "4.9.65-3+deb9u1", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-image-4.9.0-3-5kc-malta", ver: "4.9.65-3+deb9u1", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-image-4.9.0-3-5kc-malta-dbg", ver: "4.9.65-3+deb9u1", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-image-4.9.0-3-686", ver: "4.9.65-3+deb9u1", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-image-4.9.0-3-686-dbg", ver: "4.9.65-3+deb9u1", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-image-4.9.0-3-686-pae", ver: "4.9.65-3+deb9u1", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-image-4.9.0-3-686-pae-dbg", ver: "4.9.65-3+deb9u1", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-image-4.9.0-3-amd64", ver: "4.9.65-3+deb9u1", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-image-4.9.0-3-amd64-dbg", ver: "4.9.65-3+deb9u1", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-image-4.9.0-3-arm64", ver: "4.9.65-3+deb9u1", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-image-4.9.0-3-arm64-dbg", ver: "4.9.65-3+deb9u1", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-image-4.9.0-3-armmp", ver: "4.9.65-3+deb9u1", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-image-4.9.0-3-armmp-dbg", ver: "4.9.65-3+deb9u1", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-image-4.9.0-3-armmp-lpae", ver: "4.9.65-3+deb9u1", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-image-4.9.0-3-armmp-lpae-dbg", ver: "4.9.65-3+deb9u1", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-image-4.9.0-3-loongson-3", ver: "4.9.65-3+deb9u1", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-image-4.9.0-3-loongson-3-dbg", ver: "4.9.65-3+deb9u1", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-image-4.9.0-3-marvell", ver: "4.9.65-3+deb9u1", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-image-4.9.0-3-marvell-dbg", ver: "4.9.65-3+deb9u1", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-image-4.9.0-3-octeon", ver: "4.9.65-3+deb9u1", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-image-4.9.0-3-octeon-dbg", ver: "4.9.65-3+deb9u1", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-image-4.9.0-3-powerpc64le", ver: "4.9.65-3+deb9u1", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-image-4.9.0-3-powerpc64le-dbg", ver: "4.9.65-3+deb9u1", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-image-4.9.0-3-rt-686-pae", ver: "4.9.65-3+deb9u1", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-image-4.9.0-3-rt-686-pae-dbg", ver: "4.9.65-3+deb9u1", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-image-4.9.0-3-rt-amd64", ver: "4.9.65-3+deb9u1", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-image-4.9.0-3-rt-amd64-dbg", ver: "4.9.65-3+deb9u1", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-image-4.9.0-3-s390x", ver: "4.9.65-3+deb9u1", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-image-4.9.0-3-s390x-dbg", ver: "4.9.65-3+deb9u1", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-image-4.9.0-4-4kc-malta", ver: "4.9.65-3+deb9u1", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-image-4.9.0-4-4kc-malta-dbg", ver: "4.9.65-3+deb9u1", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-image-4.9.0-4-5kc-malta", ver: "4.9.65-3+deb9u1", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-image-4.9.0-4-5kc-malta-dbg", ver: "4.9.65-3+deb9u1", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-image-4.9.0-4-686", ver: "4.9.65-3+deb9u1", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-image-4.9.0-4-686-dbg", ver: "4.9.65-3+deb9u1", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-image-4.9.0-4-686-pae", ver: "4.9.65-3+deb9u1", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-image-4.9.0-4-686-pae-dbg", ver: "4.9.65-3+deb9u1", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-image-4.9.0-4-amd64", ver: "4.9.65-3+deb9u1", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-image-4.9.0-4-amd64-dbg", ver: "4.9.65-3+deb9u1", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-image-4.9.0-4-arm64", ver: "4.9.65-3+deb9u1", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-image-4.9.0-4-arm64-dbg", ver: "4.9.65-3+deb9u1", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-image-4.9.0-4-armmp", ver: "4.9.65-3+deb9u1", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-image-4.9.0-4-armmp-dbg", ver: "4.9.65-3+deb9u1", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-image-4.9.0-4-armmp-lpae", ver: "4.9.65-3+deb9u1", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-image-4.9.0-4-armmp-lpae-dbg", ver: "4.9.65-3+deb9u1", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-image-4.9.0-4-loongson-3", ver: "4.9.65-3+deb9u1", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-image-4.9.0-4-loongson-3-dbg", ver: "4.9.65-3+deb9u1", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-image-4.9.0-4-marvell", ver: "4.9.65-3+deb9u1", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-image-4.9.0-4-marvell-dbg", ver: "4.9.65-3+deb9u1", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-image-4.9.0-4-octeon", ver: "4.9.65-3+deb9u1", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-image-4.9.0-4-octeon-dbg", ver: "4.9.65-3+deb9u1", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-image-4.9.0-4-powerpc64le", ver: "4.9.65-3+deb9u1", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-image-4.9.0-4-powerpc64le-dbg", ver: "4.9.65-3+deb9u1", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-image-4.9.0-4-rt-686-pae", ver: "4.9.65-3+deb9u1", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-image-4.9.0-4-rt-686-pae-dbg", ver: "4.9.65-3+deb9u1", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-image-4.9.0-4-rt-amd64", ver: "4.9.65-3+deb9u1", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-image-4.9.0-4-rt-amd64-dbg", ver: "4.9.65-3+deb9u1", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-image-4.9.0-4-s390x", ver: "4.9.65-3+deb9u1", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-image-4.9.0-4-s390x-dbg", ver: "4.9.65-3+deb9u1", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-kbuild-4.9", ver: "4.9.65-3+deb9u1", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-libc-dev", ver: "4.9.65-3+deb9u1", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-manual-4.9", ver: "4.9.65-3+deb9u1", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-perf-4.9", ver: "4.9.65-3+deb9u1", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-source-4.9", ver: "4.9.65-3+deb9u1", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-support-4.9.0-3", ver: "4.9.65-3+deb9u1", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-support-4.9.0-4", ver: "4.9.65-3+deb9u1", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "usbip", ver: "4.9.65-3+deb9u1", rls: "DEB9" ) )){
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

