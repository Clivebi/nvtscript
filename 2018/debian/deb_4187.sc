if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.704187" );
	script_version( "2021-06-16T02:47:07+0000" );
	script_cve_id( "CVE-2015-9016", "CVE-2017-0861", "CVE-2017-13166", "CVE-2017-13220", "CVE-2017-16526", "CVE-2017-16911", "CVE-2017-16912", "CVE-2017-16913", "CVE-2017-16914", "CVE-2017-18017", "CVE-2017-18203", "CVE-2017-18216", "CVE-2017-18232", "CVE-2017-18241", "CVE-2017-5715", "CVE-2017-5753", "CVE-2018-1000004", "CVE-2018-1000199", "CVE-2018-1066", "CVE-2018-1068", "CVE-2018-1092", "CVE-2018-5332", "CVE-2018-5333", "CVE-2018-5750", "CVE-2018-5803", "CVE-2018-6927", "CVE-2018-7492", "CVE-2018-7566", "CVE-2018-7740", "CVE-2018-7757", "CVE-2018-7995", "CVE-2018-8781", "CVE-2018-8822" );
	script_name( "Debian Security Advisory DSA 4187-1 (linux - security update)" );
	script_tag( name: "last_modification", value: "2021-06-16 02:47:07 +0000 (Wed, 16 Jun 2021)" );
	script_tag( name: "creation_date", value: "2018-05-01 00:00:00 +0200 (Tue, 01 May 2018)" );
	script_tag( name: "cvss_base", value: "10.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:C/A:C" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2018-11-30 21:31:00 +0000 (Fri, 30 Nov 2018)" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	script_xref( name: "URL", value: "https://www.debian.org/security/2018/dsa-4187.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB8" );
	script_tag( name: "affected", value: "linux on Debian Linux" );
	script_tag( name: "solution", value: "For the oldstable distribution (jessie), these problems have been fixed
in version 3.16.56-1.

We recommend that you upgrade your linux packages." );
	script_xref( name: "URL", value: "https://security-tracker.debian.org/tracker/linux" );
	script_tag( name: "summary", value: "Several vulnerabilities have been discovered in the Linux kernel that
may lead to a privilege escalation, denial of service or information
leaks.

CVE-2015-9016
Ming Lei reported a race condition in the multiqueue block layer
(blk-mq). On a system with a driver using blk-mq (mtip32xx,
null_blk, or virtio_blk), a local user might be able to use this
for denial of service or possibly for privilege escalation.

CVE-2017-0861
Robb Glasser reported a potential use-after-free in the ALSA (sound)
PCM core. We believe this was not possible in practice.

Description truncated. Please see the references for more information." );
	script_tag( name: "vuldetect", value: "This check tests the installed software version using the apt package manager." );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(!isnull( res = isdpkgvuln( pkg: "linux-compiler-gcc-4.8-arm", ver: "3.16.56-1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-compiler-gcc-4.8-s390", ver: "3.16.56-1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-compiler-gcc-4.8-x86", ver: "3.16.56-1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-compiler-gcc-4.9-x86", ver: "3.16.56-1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-doc-3.16", ver: "3.16.56-1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-headers-3.16.0-4-4kc-malta", ver: "3.16.56-1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-headers-3.16.0-4-586", ver: "3.16.56-1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-headers-3.16.0-4-5kc-malta", ver: "3.16.56-1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-headers-3.16.0-4-686-pae", ver: "3.16.56-1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-headers-3.16.0-4-all", ver: "3.16.56-1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-headers-3.16.0-4-all-amd64", ver: "3.16.56-1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-headers-3.16.0-4-all-arm64", ver: "3.16.56-1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-headers-3.16.0-4-all-armel", ver: "3.16.56-1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-headers-3.16.0-4-all-armhf", ver: "3.16.56-1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-headers-3.16.0-4-all-i386", ver: "3.16.56-1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-headers-3.16.0-4-all-mips", ver: "3.16.56-1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-headers-3.16.0-4-all-mipsel", ver: "3.16.56-1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-headers-3.16.0-4-all-powerpc", ver: "3.16.56-1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-headers-3.16.0-4-all-ppc64el", ver: "3.16.56-1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-headers-3.16.0-4-all-s390x", ver: "3.16.56-1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-headers-3.16.0-4-amd64", ver: "3.16.56-1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-headers-3.16.0-4-arm64", ver: "3.16.56-1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-headers-3.16.0-4-armmp", ver: "3.16.56-1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-headers-3.16.0-4-armmp-lpae", ver: "3.16.56-1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-headers-3.16.0-4-common", ver: "3.16.56-1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-headers-3.16.0-4-ixp4xx", ver: "3.16.56-1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-headers-3.16.0-4-kirkwood", ver: "3.16.56-1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-headers-3.16.0-4-loongson-2e", ver: "3.16.56-1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-headers-3.16.0-4-loongson-2f", ver: "3.16.56-1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-headers-3.16.0-4-loongson-3", ver: "3.16.56-1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-headers-3.16.0-4-octeon", ver: "3.16.56-1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-headers-3.16.0-4-orion5x", ver: "3.16.56-1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-headers-3.16.0-4-powerpc", ver: "3.16.56-1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-headers-3.16.0-4-powerpc-smp", ver: "3.16.56-1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-headers-3.16.0-4-powerpc64", ver: "3.16.56-1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-headers-3.16.0-4-powerpc64le", ver: "3.16.56-1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-headers-3.16.0-4-r4k-ip22", ver: "3.16.56-1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-headers-3.16.0-4-r5k-ip32", ver: "3.16.56-1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-headers-3.16.0-4-s390x", ver: "3.16.56-1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-headers-3.16.0-4-sb1-bcm91250a", ver: "3.16.56-1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-headers-3.16.0-4-versatile", ver: "3.16.56-1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-headers-3.16.0-5-4kc-malta", ver: "3.16.56-1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-headers-3.16.0-5-586", ver: "3.16.56-1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-headers-3.16.0-5-5kc-malta", ver: "3.16.56-1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-headers-3.16.0-5-686-pae", ver: "3.16.56-1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-headers-3.16.0-5-all", ver: "3.16.56-1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-headers-3.16.0-5-all-amd64", ver: "3.16.56-1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-headers-3.16.0-5-all-arm64", ver: "3.16.56-1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-headers-3.16.0-5-all-armel", ver: "3.16.56-1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-headers-3.16.0-5-all-armhf", ver: "3.16.56-1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-headers-3.16.0-5-all-i386", ver: "3.16.56-1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-headers-3.16.0-5-all-mips", ver: "3.16.56-1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-headers-3.16.0-5-all-mipsel", ver: "3.16.56-1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-headers-3.16.0-5-all-powerpc", ver: "3.16.56-1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-headers-3.16.0-5-all-ppc64el", ver: "3.16.56-1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-headers-3.16.0-5-all-s390x", ver: "3.16.56-1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-headers-3.16.0-5-amd64", ver: "3.16.56-1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-headers-3.16.0-5-arm64", ver: "3.16.56-1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-headers-3.16.0-5-armmp", ver: "3.16.56-1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-headers-3.16.0-5-armmp-lpae", ver: "3.16.56-1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-headers-3.16.0-5-common", ver: "3.16.56-1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-headers-3.16.0-5-ixp4xx", ver: "3.16.56-1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-headers-3.16.0-5-kirkwood", ver: "3.16.56-1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-headers-3.16.0-5-loongson-2e", ver: "3.16.56-1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-headers-3.16.0-5-loongson-2f", ver: "3.16.56-1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-headers-3.16.0-5-loongson-3", ver: "3.16.56-1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-headers-3.16.0-5-octeon", ver: "3.16.56-1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-headers-3.16.0-5-orion5x", ver: "3.16.56-1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-headers-3.16.0-5-powerpc", ver: "3.16.56-1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-headers-3.16.0-5-powerpc-smp", ver: "3.16.56-1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-headers-3.16.0-5-powerpc64", ver: "3.16.56-1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-headers-3.16.0-5-powerpc64le", ver: "3.16.56-1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-headers-3.16.0-5-r4k-ip22", ver: "3.16.56-1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-headers-3.16.0-5-r5k-ip32", ver: "3.16.56-1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-headers-3.16.0-5-s390x", ver: "3.16.56-1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-headers-3.16.0-5-sb1-bcm91250a", ver: "3.16.56-1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-headers-3.16.0-5-versatile", ver: "3.16.56-1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-headers-3.16.0-6-4kc-malta", ver: "3.16.56-1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-headers-3.16.0-6-586", ver: "3.16.56-1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-headers-3.16.0-6-5kc-malta", ver: "3.16.56-1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-headers-3.16.0-6-686-pae", ver: "3.16.56-1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-headers-3.16.0-6-all", ver: "3.16.56-1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-headers-3.16.0-6-all-amd64", ver: "3.16.56-1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-headers-3.16.0-6-all-arm64", ver: "3.16.56-1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-headers-3.16.0-6-all-armel", ver: "3.16.56-1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-headers-3.16.0-6-all-armhf", ver: "3.16.56-1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-headers-3.16.0-6-all-i386", ver: "3.16.56-1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-headers-3.16.0-6-all-mips", ver: "3.16.56-1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-headers-3.16.0-6-all-powerpc", ver: "3.16.56-1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-headers-3.16.0-6-all-ppc64el", ver: "3.16.56-1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-headers-3.16.0-6-all-s390x", ver: "3.16.56-1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-headers-3.16.0-6-amd64", ver: "3.16.56-1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-headers-3.16.0-6-arm64", ver: "3.16.56-1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-headers-3.16.0-6-armmp", ver: "3.16.56-1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-headers-3.16.0-6-armmp-lpae", ver: "3.16.56-1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-headers-3.16.0-6-common", ver: "3.16.56-1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-headers-3.16.0-6-ixp4xx", ver: "3.16.56-1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-headers-3.16.0-6-kirkwood", ver: "3.16.56-1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-headers-3.16.0-6-octeon", ver: "3.16.56-1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-headers-3.16.0-6-orion5x", ver: "3.16.56-1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-headers-3.16.0-6-powerpc", ver: "3.16.56-1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-headers-3.16.0-6-powerpc-smp", ver: "3.16.56-1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-headers-3.16.0-6-powerpc64", ver: "3.16.56-1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-headers-3.16.0-6-powerpc64le", ver: "3.16.56-1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-headers-3.16.0-6-r4k-ip22", ver: "3.16.56-1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-headers-3.16.0-6-r5k-ip32", ver: "3.16.56-1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-headers-3.16.0-6-s390x", ver: "3.16.56-1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-headers-3.16.0-6-sb1-bcm91250a", ver: "3.16.56-1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-headers-3.16.0-6-versatile", ver: "3.16.56-1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-image-3.16.0-4-4kc-malta", ver: "3.16.56-1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-image-3.16.0-4-586", ver: "3.16.56-1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-image-3.16.0-4-5kc-malta", ver: "3.16.56-1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-image-3.16.0-4-686-pae", ver: "3.16.56-1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-image-3.16.0-4-686-pae-dbg", ver: "3.16.56-1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-image-3.16.0-4-amd64", ver: "3.16.56-1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-image-3.16.0-4-amd64-dbg", ver: "3.16.56-1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-image-3.16.0-4-arm64", ver: "3.16.56-1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-image-3.16.0-4-arm64-dbg", ver: "3.16.56-1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-image-3.16.0-4-armmp", ver: "3.16.56-1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-image-3.16.0-4-armmp-lpae", ver: "3.16.56-1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-image-3.16.0-4-ixp4xx", ver: "3.16.56-1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-image-3.16.0-4-kirkwood", ver: "3.16.56-1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-image-3.16.0-4-loongson-2e", ver: "3.16.56-1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-image-3.16.0-4-loongson-2f", ver: "3.16.56-1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-image-3.16.0-4-loongson-3", ver: "3.16.56-1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-image-3.16.0-4-octeon", ver: "3.16.56-1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-image-3.16.0-4-orion5x", ver: "3.16.56-1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-image-3.16.0-4-powerpc", ver: "3.16.56-1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-image-3.16.0-4-powerpc-smp", ver: "3.16.56-1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-image-3.16.0-4-powerpc64", ver: "3.16.56-1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-image-3.16.0-4-powerpc64le", ver: "3.16.56-1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-image-3.16.0-4-r4k-ip22", ver: "3.16.56-1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-image-3.16.0-4-r5k-ip32", ver: "3.16.56-1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-image-3.16.0-4-s390x", ver: "3.16.56-1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-image-3.16.0-4-s390x-dbg", ver: "3.16.56-1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-image-3.16.0-4-sb1-bcm91250a", ver: "3.16.56-1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-image-3.16.0-4-versatile", ver: "3.16.56-1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-image-3.16.0-5-4kc-malta", ver: "3.16.56-1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-image-3.16.0-5-586", ver: "3.16.56-1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-image-3.16.0-5-5kc-malta", ver: "3.16.56-1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-image-3.16.0-5-686-pae", ver: "3.16.56-1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-image-3.16.0-5-686-pae-dbg", ver: "3.16.56-1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-image-3.16.0-5-amd64", ver: "3.16.56-1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-image-3.16.0-5-amd64-dbg", ver: "3.16.56-1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-image-3.16.0-5-arm64", ver: "3.16.56-1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-image-3.16.0-5-arm64-dbg", ver: "3.16.56-1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-image-3.16.0-5-armmp", ver: "3.16.56-1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-image-3.16.0-5-armmp-lpae", ver: "3.16.56-1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-image-3.16.0-5-ixp4xx", ver: "3.16.56-1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-image-3.16.0-5-kirkwood", ver: "3.16.56-1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-image-3.16.0-5-loongson-2e", ver: "3.16.56-1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-image-3.16.0-5-loongson-2f", ver: "3.16.56-1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-image-3.16.0-5-loongson-3", ver: "3.16.56-1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-image-3.16.0-5-octeon", ver: "3.16.56-1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-image-3.16.0-5-orion5x", ver: "3.16.56-1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-image-3.16.0-5-powerpc", ver: "3.16.56-1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-image-3.16.0-5-powerpc-smp", ver: "3.16.56-1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-image-3.16.0-5-powerpc64", ver: "3.16.56-1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-image-3.16.0-5-powerpc64le", ver: "3.16.56-1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-image-3.16.0-5-r4k-ip22", ver: "3.16.56-1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-image-3.16.0-5-r5k-ip32", ver: "3.16.56-1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-image-3.16.0-5-s390x", ver: "3.16.56-1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-image-3.16.0-5-s390x-dbg", ver: "3.16.56-1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-image-3.16.0-5-sb1-bcm91250a", ver: "3.16.56-1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-image-3.16.0-5-versatile", ver: "3.16.56-1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-image-3.16.0-6-4kc-malta", ver: "3.16.56-1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-image-3.16.0-6-586", ver: "3.16.56-1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-image-3.16.0-6-5kc-malta", ver: "3.16.56-1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-image-3.16.0-6-686-pae", ver: "3.16.56-1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-image-3.16.0-6-686-pae-dbg", ver: "3.16.56-1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-image-3.16.0-6-amd64", ver: "3.16.56-1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-image-3.16.0-6-amd64-dbg", ver: "3.16.56-1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-image-3.16.0-6-arm64", ver: "3.16.56-1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-image-3.16.0-6-arm64-dbg", ver: "3.16.56-1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-image-3.16.0-6-armmp", ver: "3.16.56-1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-image-3.16.0-6-armmp-lpae", ver: "3.16.56-1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-image-3.16.0-6-ixp4xx", ver: "3.16.56-1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-image-3.16.0-6-kirkwood", ver: "3.16.56-1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-image-3.16.0-6-octeon", ver: "3.16.56-1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-image-3.16.0-6-orion5x", ver: "3.16.56-1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-image-3.16.0-6-powerpc", ver: "3.16.56-1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-image-3.16.0-6-powerpc-smp", ver: "3.16.56-1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-image-3.16.0-6-powerpc64", ver: "3.16.56-1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-image-3.16.0-6-powerpc64le", ver: "3.16.56-1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-image-3.16.0-6-r4k-ip22", ver: "3.16.56-1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-image-3.16.0-6-r5k-ip32", ver: "3.16.56-1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-image-3.16.0-6-s390x", ver: "3.16.56-1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-image-3.16.0-6-s390x-dbg", ver: "3.16.56-1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-image-3.16.0-6-sb1-bcm91250a", ver: "3.16.56-1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-image-3.16.0-6-versatile", ver: "3.16.56-1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-libc-dev", ver: "3.16.56-1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-manual-3.16", ver: "3.16.56-1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-source-3.16", ver: "3.16.56-1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-support-3.16.0-4", ver: "3.16.56-1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-support-3.16.0-5", ver: "3.16.56-1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-support-3.16.0-6", ver: "3.16.56-1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "xen-linux-system-3.16.0-4-amd64", ver: "3.16.56-1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "xen-linux-system-3.16.0-5-amd64", ver: "3.16.56-1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "xen-linux-system-3.16.0-6-amd64", ver: "3.16.56-1", rls: "DEB8" ) )){
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

