if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.891099" );
	script_version( "2021-06-21T02:00:27+0000" );
	script_cve_id( "CVE-2017-1000111", "CVE-2017-1000251", "CVE-2017-1000363", "CVE-2017-1000365", "CVE-2017-1000380", "CVE-2017-10661", "CVE-2017-10911", "CVE-2017-11176", "CVE-2017-11600", "CVE-2017-12134", "CVE-2017-12153", "CVE-2017-12154", "CVE-2017-14106", "CVE-2017-14140", "CVE-2017-14156", "CVE-2017-14340", "CVE-2017-14489", "CVE-2017-7482", "CVE-2017-7542", "CVE-2017-7889" );
	script_name( "Debian LTS: Security Advisory for linux (DLA-1099-1)" );
	script_tag( name: "last_modification", value: "2021-06-21 02:00:27 +0000 (Mon, 21 Jun 2021)" );
	script_tag( name: "creation_date", value: "2018-02-07 00:00:00 +0100 (Wed, 07 Feb 2018)" );
	script_tag( name: "cvss_base", value: "7.7" );
	script_tag( name: "cvss_base_vector", value: "AV:A/AC:L/Au:S/C:C/I:C/A:C" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:A/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-06-03 19:00:00 +0000 (Wed, 03 Jun 2020)" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	script_xref( name: "URL", value: "https://lists.debian.org/debian-lts-announce/2017/09/msg00017.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH http://greenbone.net" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB7" );
	script_tag( name: "affected", value: "linux on Debian Linux" );
	script_tag( name: "solution", value: "For Debian 7 'Wheezy', these problems have been fixed in version
3.2.93-1. This version also includes bug fixes from upstream versions
up to and including 3.2.93.

For Debian 8 'Jessie', these problems have been fixed in version
3.16.43-2+deb8u4 or were fixed in an earlier version.

For Debian 9 'Stretch', these problems have been fixed in version
4.9.30-2+deb9u4 or were fixed in an earlier version.

We recommend that you upgrade your linux packages." );
	script_tag( name: "summary", value: "Several vulnerabilities have been discovered in the Linux kernel that
may lead to a privilege escalation, denial of service or information
leaks.

CVE-2017-7482

Shi Lei discovered that RxRPC Kerberos 5 ticket handling code does
not properly verify metadata, leading to information disclosure,
denial of service or potentially execution of arbitrary code.

CVE-2017-7542

An integer overflow vulnerability in the ip6_find_1stfragopt()
function was found allowing a local attacker with privileges to open
raw sockets to cause a denial of service.

CVE-2017-7889

Tommi Rantala and Brad Spengler reported that the mm subsystem does
not properly enforce the CONFIG_STRICT_DEVMEM protection mechanism,
allowing a local attacker with access to /dev/mem to obtain
sensitive information or potentially execute arbitrary code.

Description truncated. Please see the references for more information.

For Debian 7 'Wheezy', these problems have been fixed in version
3.2.93-1. This version also includes bug fixes from upstream versions
up to and including 3.2.93.

For Debian 8 'Jessie', these problems have been fixed in version
3.16.43-2+deb8u4 or were fixed in an earlier version." );
	script_tag( name: "vuldetect", value: "This check tests the installed software version using the apt package manager." );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(!isnull( res = isdpkgvuln( pkg: "linux-doc-3.2", ver: "3.2.93-1", rls: "DEB7" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-headers-3.2.0-4-486", ver: "3.2.93-1", rls: "DEB7" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-headers-3.2.0-4-686-pae", ver: "3.2.93-1", rls: "DEB7" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-headers-3.2.0-4-all", ver: "3.2.93-1", rls: "DEB7" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-headers-3.2.0-4-all-amd64", ver: "3.2.93-1", rls: "DEB7" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-headers-3.2.0-4-all-armel", ver: "3.2.93-1", rls: "DEB7" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-headers-3.2.0-4-all-armhf", ver: "3.2.93-1", rls: "DEB7" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-headers-3.2.0-4-all-i386", ver: "3.2.93-1", rls: "DEB7" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-headers-3.2.0-4-amd64", ver: "3.2.93-1", rls: "DEB7" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-headers-3.2.0-4-common", ver: "3.2.93-1", rls: "DEB7" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-headers-3.2.0-4-common-rt", ver: "3.2.93-1", rls: "DEB7" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-headers-3.2.0-4-iop32x", ver: "3.2.93-1", rls: "DEB7" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-headers-3.2.0-4-ixp4xx", ver: "3.2.93-1", rls: "DEB7" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-headers-3.2.0-4-kirkwood", ver: "3.2.93-1", rls: "DEB7" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-headers-3.2.0-4-mv78xx0", ver: "3.2.93-1", rls: "DEB7" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-headers-3.2.0-4-mx5", ver: "3.2.93-1", rls: "DEB7" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-headers-3.2.0-4-omap", ver: "3.2.93-1", rls: "DEB7" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-headers-3.2.0-4-orion5x", ver: "3.2.93-1", rls: "DEB7" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-headers-3.2.0-4-rt-686-pae", ver: "3.2.93-1", rls: "DEB7" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-headers-3.2.0-4-rt-amd64", ver: "3.2.93-1", rls: "DEB7" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-headers-3.2.0-4-versatile", ver: "3.2.93-1", rls: "DEB7" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-headers-3.2.0-4-vexpress", ver: "3.2.93-1", rls: "DEB7" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-headers-3.2.0-5-486", ver: "3.2.93-1", rls: "DEB7" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-headers-3.2.0-5-686-pae", ver: "3.2.93-1", rls: "DEB7" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-headers-3.2.0-5-all", ver: "3.2.93-1", rls: "DEB7" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-headers-3.2.0-5-all-amd64", ver: "3.2.93-1", rls: "DEB7" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-headers-3.2.0-5-all-armel", ver: "3.2.93-1", rls: "DEB7" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-headers-3.2.0-5-all-armhf", ver: "3.2.93-1", rls: "DEB7" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-headers-3.2.0-5-all-i386", ver: "3.2.93-1", rls: "DEB7" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-headers-3.2.0-5-amd64", ver: "3.2.93-1", rls: "DEB7" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-headers-3.2.0-5-common", ver: "3.2.93-1", rls: "DEB7" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-headers-3.2.0-5-common-rt", ver: "3.2.93-1", rls: "DEB7" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-headers-3.2.0-5-iop32x", ver: "3.2.93-1", rls: "DEB7" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-headers-3.2.0-5-ixp4xx", ver: "3.2.93-1", rls: "DEB7" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-headers-3.2.0-5-kirkwood", ver: "3.2.93-1", rls: "DEB7" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-headers-3.2.0-5-mv78xx0", ver: "3.2.93-1", rls: "DEB7" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-headers-3.2.0-5-mx5", ver: "3.2.93-1", rls: "DEB7" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-headers-3.2.0-5-omap", ver: "3.2.93-1", rls: "DEB7" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-headers-3.2.0-5-orion5x", ver: "3.2.93-1", rls: "DEB7" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-headers-3.2.0-5-rt-686-pae", ver: "3.2.93-1", rls: "DEB7" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-headers-3.2.0-5-rt-amd64", ver: "3.2.93-1", rls: "DEB7" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-headers-3.2.0-5-versatile", ver: "3.2.93-1", rls: "DEB7" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-headers-3.2.0-5-vexpress", ver: "3.2.93-1", rls: "DEB7" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-image-3.2.0-4-486", ver: "3.2.93-1", rls: "DEB7" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-image-3.2.0-4-686-pae", ver: "3.2.93-1", rls: "DEB7" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-image-3.2.0-4-686-pae-dbg", ver: "3.2.93-1", rls: "DEB7" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-image-3.2.0-4-amd64", ver: "3.2.93-1", rls: "DEB7" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-image-3.2.0-4-amd64-dbg", ver: "3.2.93-1", rls: "DEB7" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-image-3.2.0-4-iop32x", ver: "3.2.93-1", rls: "DEB7" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-image-3.2.0-4-ixp4xx", ver: "3.2.93-1", rls: "DEB7" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-image-3.2.0-4-kirkwood", ver: "3.2.93-1", rls: "DEB7" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-image-3.2.0-4-mv78xx0", ver: "3.2.93-1", rls: "DEB7" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-image-3.2.0-4-mx5", ver: "3.2.93-1", rls: "DEB7" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-image-3.2.0-4-omap", ver: "3.2.93-1", rls: "DEB7" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-image-3.2.0-4-orion5x", ver: "3.2.93-1", rls: "DEB7" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-image-3.2.0-4-rt-686-pae", ver: "3.2.93-1", rls: "DEB7" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-image-3.2.0-4-rt-686-pae-dbg", ver: "3.2.93-1", rls: "DEB7" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-image-3.2.0-4-rt-amd64", ver: "3.2.93-1", rls: "DEB7" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-image-3.2.0-4-rt-amd64-dbg", ver: "3.2.93-1", rls: "DEB7" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-image-3.2.0-4-versatile", ver: "3.2.93-1", rls: "DEB7" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-image-3.2.0-4-vexpress", ver: "3.2.93-1", rls: "DEB7" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-image-3.2.0-5-486", ver: "3.2.93-1", rls: "DEB7" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-image-3.2.0-5-686-pae", ver: "3.2.93-1", rls: "DEB7" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-image-3.2.0-5-686-pae-dbg", ver: "3.2.93-1", rls: "DEB7" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-image-3.2.0-5-amd64", ver: "3.2.93-1", rls: "DEB7" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-image-3.2.0-5-amd64-dbg", ver: "3.2.93-1", rls: "DEB7" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-image-3.2.0-5-iop32x", ver: "3.2.93-1", rls: "DEB7" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-image-3.2.0-5-ixp4xx", ver: "3.2.93-1", rls: "DEB7" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-image-3.2.0-5-kirkwood", ver: "3.2.93-1", rls: "DEB7" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-image-3.2.0-5-mv78xx0", ver: "3.2.93-1", rls: "DEB7" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-image-3.2.0-5-mx5", ver: "3.2.93-1", rls: "DEB7" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-image-3.2.0-5-omap", ver: "3.2.93-1", rls: "DEB7" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-image-3.2.0-5-orion5x", ver: "3.2.93-1", rls: "DEB7" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-image-3.2.0-5-rt-686-pae", ver: "3.2.93-1", rls: "DEB7" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-image-3.2.0-5-rt-686-pae-dbg", ver: "3.2.93-1", rls: "DEB7" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-image-3.2.0-5-rt-amd64", ver: "3.2.93-1", rls: "DEB7" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-image-3.2.0-5-rt-amd64-dbg", ver: "3.2.93-1", rls: "DEB7" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-image-3.2.0-5-versatile", ver: "3.2.93-1", rls: "DEB7" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-image-3.2.0-5-vexpress", ver: "3.2.93-1", rls: "DEB7" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-libc-dev", ver: "3.2.93-1", rls: "DEB7" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-manual-3.2", ver: "3.2.93-1", rls: "DEB7" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-source-3.2", ver: "3.2.93-1", rls: "DEB7" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-support-3.2.0-4", ver: "3.2.93-1", rls: "DEB7" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-support-3.2.0-5", ver: "3.2.93-1", rls: "DEB7" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "xen-linux-system-3.2.0-4-686-pae", ver: "3.2.93-1", rls: "DEB7" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "xen-linux-system-3.2.0-4-amd64", ver: "3.2.93-1", rls: "DEB7" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "xen-linux-system-3.2.0-5-686-pae", ver: "3.2.93-1", rls: "DEB7" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "xen-linux-system-3.2.0-5-amd64", ver: "3.2.93-1", rls: "DEB7" ) )){
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

