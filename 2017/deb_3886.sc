if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.703886" );
	script_version( "2021-09-08T13:01:42+0000" );
	script_cve_id( "CVE-2017-0605", "CVE-2017-1000364", "CVE-2017-7487", "CVE-2017-7645", "CVE-2017-7895", "CVE-2017-8064", "CVE-2017-8890", "CVE-2017-8924", "CVE-2017-8925", "CVE-2017-9074", "CVE-2017-9075", "CVE-2017-9076", "CVE-2017-9077", "CVE-2017-9242" );
	script_name( "Debian Security Advisory DSA 3886-1 (linux - security update)" );
	script_tag( name: "last_modification", value: "2021-09-08 13:01:42 +0000 (Wed, 08 Sep 2021)" );
	script_tag( name: "creation_date", value: "2017-06-19 00:00:00 +0200 (Mon, 19 Jun 2017)" );
	script_tag( name: "cvss_base", value: "10.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:C/A:C" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-10-03 00:03:00 +0000 (Thu, 03 Oct 2019)" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	script_xref( name: "URL", value: "http://www.debian.org/security/2017/dsa-3886.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2017 Greenbone Networks GmbH" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB8" );
	script_tag( name: "affected", value: "linux on Debian Linux" );
	script_tag( name: "solution", value: "For the oldstable distribution (jessie), these problems have been fixed
in version 3.16.43-2+deb8u1.

For the stable distribution (stretch), these problems have been fixed in
version 4.9.30-2+deb9u1 or earlier versions before the stretch release.

We recommend that you upgrade your linux packages." );
	script_tag( name: "summary", value: "Several vulnerabilities have been discovered in the Linux kernel that
may lead to a privilege escalation, denial of service or information
leaks.

CVE-2017-0605
A buffer overflow flaw was discovered in the trace subsystem.

CVE-2017-7487
Li Qiang reported a reference counter leak in the ipxitf_ioctl
function which may result into a use-after-free vulnerability,
triggerable when a IPX interface is configured.

CVE-2017-7645
Tuomas Haanpaa and Matti Kamunen from Synopsys Ltd discovered that
the NFSv2 and NFSv3 server implementations are vulnerable to an
out-of-bounds memory access issue while processing arbitrarily long
arguments sent by NFSv2/NFSv3 PRC clients, leading to a denial of
service.

Description truncated. Please see the references for more information." );
	script_tag( name: "vuldetect", value: "This check tests the installed software version using the apt package manager." );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(( res = isdpkgvuln( pkg: "linux-compiler-gcc-4.8-arm", ver: "3.16.43-2+deb8u1", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "linux-compiler-gcc-4.8-s390", ver: "3.16.43-2+deb8u1", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "linux-compiler-gcc-4.8-x86", ver: "3.16.43-2+deb8u1", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "linux-doc-3.16", ver: "3.16.43-2+deb8u1", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "linux-headers-3.16.0-4-4kc-malta", ver: "3.16.43-2+deb8u1", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "linux-headers-3.16.0-4-586", ver: "3.16.43-2+deb8u1", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "linux-headers-3.16.0-4-5kc-malta", ver: "3.16.43-2+deb8u1", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "linux-headers-3.16.0-4-686-pae", ver: "3.16.43-2+deb8u1", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "linux-headers-3.16.0-4-all", ver: "3.16.43-2+deb8u1", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "linux-headers-3.16.0-4-all-amd64", ver: "3.16.43-2+deb8u1", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "linux-headers-3.16.0-4-all-arm64", ver: "3.16.43-2+deb8u1", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "linux-headers-3.16.0-4-all-armel", ver: "3.16.43-2+deb8u1", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "linux-headers-3.16.0-4-all-armhf", ver: "3.16.43-2+deb8u1", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "linux-headers-3.16.0-4-all-i386", ver: "3.16.43-2+deb8u1", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "linux-headers-3.16.0-4-all-mips", ver: "3.16.43-2+deb8u1", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "linux-headers-3.16.0-4-all-mipsel", ver: "3.16.43-2+deb8u1", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "linux-headers-3.16.0-4-all-powerpc", ver: "3.16.43-2+deb8u1", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "linux-headers-3.16.0-4-all-ppc64el", ver: "3.16.43-2+deb8u1", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "linux-headers-3.16.0-4-all-s390x", ver: "3.16.43-2+deb8u1", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "linux-headers-3.16.0-4-amd64", ver: "3.16.43-2+deb8u1", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "linux-headers-3.16.0-4-arm64", ver: "3.16.43-2+deb8u1", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "linux-headers-3.16.0-4-armmp", ver: "3.16.43-2+deb8u1", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "linux-headers-3.16.0-4-armmp-lpae", ver: "3.16.43-2+deb8u1", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "linux-headers-3.16.0-4-common", ver: "3.16.43-2+deb8u1", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "linux-headers-3.16.0-4-ixp4xx", ver: "3.16.43-2+deb8u1", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "linux-headers-3.16.0-4-kirkwood", ver: "3.16.43-2+deb8u1", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "linux-headers-3.16.0-4-loongson-2e", ver: "3.16.43-2+deb8u1", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "linux-headers-3.16.0-4-loongson-2f", ver: "3.16.43-2+deb8u1", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "linux-headers-3.16.0-4-loongson-3", ver: "3.16.43-2+deb8u1", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "linux-headers-3.16.0-4-octeon", ver: "3.16.43-2+deb8u1", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "linux-headers-3.16.0-4-orion5x", ver: "3.16.43-2+deb8u1", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "linux-headers-3.16.0-4-powerpc", ver: "3.16.43-2+deb8u1", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "linux-headers-3.16.0-4-powerpc-smp", ver: "3.16.43-2+deb8u1", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "linux-headers-3.16.0-4-powerpc64", ver: "3.16.43-2+deb8u1", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "linux-headers-3.16.0-4-powerpc64le", ver: "3.16.43-2+deb8u1", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "linux-headers-3.16.0-4-r4k-ip22", ver: "3.16.43-2+deb8u1", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "linux-headers-3.16.0-4-r5k-ip32", ver: "3.16.43-2+deb8u1", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "linux-headers-3.16.0-4-s390x", ver: "3.16.43-2+deb8u1", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "linux-headers-3.16.0-4-sb1-bcm91250a", ver: "3.16.43-2+deb8u1", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "linux-headers-3.16.0-4-versatile", ver: "3.16.43-2+deb8u1", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "linux-headers-3.2.0-4-4kc-malta", ver: "3.16.43-2+deb8u1", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "linux-headers-3.2.0-4-5kc-malta", ver: "3.16.43-2+deb8u1", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "linux-headers-3.2.0-4-all", ver: "3.16.43-2+deb8u1", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "linux-headers-3.2.0-4-all-mips", ver: "3.16.43-2+deb8u1", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "linux-headers-3.2.0-4-all-mipsel", ver: "3.16.43-2+deb8u1", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "linux-headers-3.2.0-4-common", ver: "3.16.43-2+deb8u1", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "linux-headers-3.2.0-4-loongson-2f", ver: "3.16.43-2+deb8u1", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "linux-headers-3.2.0-4-octeon", ver: "3.16.43-2+deb8u1", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "linux-headers-3.2.0-4-r4k-ip22", ver: "3.16.43-2+deb8u1", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "linux-headers-3.2.0-4-r5k-cobalt", ver: "3.16.43-2+deb8u1", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "linux-headers-3.2.0-4-r5k-ip32", ver: "3.16.43-2+deb8u1", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "linux-headers-3.2.0-4-sb1-bcm91250a", ver: "3.16.43-2+deb8u1", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "linux-headers-3.2.0-4-sb1a-bcm91480b", ver: "3.16.43-2+deb8u1", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "linux-image-3.16.0-4-4kc-malta", ver: "3.16.43-2+deb8u1", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "linux-image-3.16.0-4-586", ver: "3.16.43-2+deb8u1", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "linux-image-3.16.0-4-5kc-malta", ver: "3.16.43-2+deb8u1", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "linux-image-3.16.0-4-686-pae", ver: "3.16.43-2+deb8u1", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "linux-image-3.16.0-4-686-pae-dbg", ver: "3.16.43-2+deb8u1", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "linux-image-3.16.0-4-amd64", ver: "3.16.43-2+deb8u1", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "linux-image-3.16.0-4-amd64-dbg", ver: "3.16.43-2+deb8u1", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "linux-image-3.16.0-4-arm64", ver: "3.16.43-2+deb8u1", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "linux-image-3.16.0-4-arm64-dbg", ver: "3.16.43-2+deb8u1", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "linux-image-3.16.0-4-armmp", ver: "3.16.43-2+deb8u1", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "linux-image-3.16.0-4-armmp-lpae", ver: "3.16.43-2+deb8u1", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "linux-image-3.16.0-4-ixp4xx", ver: "3.16.43-2+deb8u1", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "linux-image-3.16.0-4-kirkwood", ver: "3.16.43-2+deb8u1", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "linux-image-3.16.0-4-loongson-2e", ver: "3.16.43-2+deb8u1", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "linux-image-3.16.0-4-loongson-2f", ver: "3.16.43-2+deb8u1", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "linux-image-3.16.0-4-loongson-3", ver: "3.16.43-2+deb8u1", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "linux-image-3.16.0-4-octeon", ver: "3.16.43-2+deb8u1", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "linux-image-3.16.0-4-orion5x", ver: "3.16.43-2+deb8u1", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "linux-image-3.16.0-4-powerpc", ver: "3.16.43-2+deb8u1", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "linux-image-3.16.0-4-powerpc-smp", ver: "3.16.43-2+deb8u1", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "linux-image-3.16.0-4-powerpc64", ver: "3.16.43-2+deb8u1", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "linux-image-3.16.0-4-powerpc64le", ver: "3.16.43-2+deb8u1", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "linux-image-3.16.0-4-r4k-ip22", ver: "3.16.43-2+deb8u1", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "linux-image-3.16.0-4-r5k-ip32", ver: "3.16.43-2+deb8u1", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "linux-image-3.16.0-4-s390x", ver: "3.16.43-2+deb8u1", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "linux-image-3.16.0-4-s390x-dbg", ver: "3.16.43-2+deb8u1", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "linux-image-3.16.0-4-sb1-bcm91250a", ver: "3.16.43-2+deb8u1", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "linux-image-3.16.0-4-versatile", ver: "3.16.43-2+deb8u1", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "linux-image-3.2.0-4-4kc-malta", ver: "3.16.43-2+deb8u1", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "linux-image-3.2.0-4-5kc-malta", ver: "3.16.43-2+deb8u1", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "linux-image-3.2.0-4-loongson-2f", ver: "3.16.43-2+deb8u1", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "linux-image-3.2.0-4-octeon", ver: "3.16.43-2+deb8u1", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "linux-image-3.2.0-4-r4k-ip22", ver: "3.16.43-2+deb8u1", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "linux-image-3.2.0-4-r5k-cobalt", ver: "3.16.43-2+deb8u1", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "linux-image-3.2.0-4-r5k-ip32", ver: "3.16.43-2+deb8u1", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "linux-image-3.2.0-4-sb1-bcm91250a", ver: "3.16.43-2+deb8u1", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "linux-image-3.2.0-4-sb1a-bcm91480b", ver: "3.16.43-2+deb8u1", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "linux-libc-dev", ver: "3.16.43-2+deb8u1", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "linux-manual-3.16", ver: "3.16.43-2+deb8u1", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "linux-source-3.16", ver: "3.16.43-2+deb8u1", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "linux-support-3.16.0-4", ver: "3.16.43-2+deb8u1", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "xen-linux-system-3.16.0-4-amd64", ver: "3.16.43-2+deb8u1", rls: "DEB8" ) ) != NULL){
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

