if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.703480" );
	script_version( "2021-09-20T13:38:59+0000" );
	script_cve_id( "CVE-2014-8121", "CVE-2015-1781", "CVE-2015-7547", "CVE-2015-8776", "CVE-2015-8777", "CVE-2015-8778", "CVE-2015-8779" );
	script_name( "Debian Security Advisory DSA 3480-1 (eglibc - security update)" );
	script_tag( name: "last_modification", value: "2021-09-20 13:38:59 +0000 (Mon, 20 Sep 2021)" );
	script_tag( name: "creation_date", value: "2016-02-16 00:00:00 +0100 (Tue, 16 Feb 2016)" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2018-10-30 16:27:00 +0000 (Tue, 30 Oct 2018)" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	script_xref( name: "URL", value: "http://www.debian.org/security/2016/dsa-3480.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2016 Greenbone Networks GmbH" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB7" );
	script_tag( name: "affected", value: "eglibc on Debian Linux" );
	script_tag( name: "solution", value: "For the oldstable distribution (wheezy),
these problems have been fixed in version 2.13-38+deb7u10.

We recommend that you upgrade your eglibc packages." );
	script_tag( name: "summary", value: "Several vulnerabilities have been fixed
in the GNU C Library, eglibc.

The CVE-2015-7547
vulnerability listed below is considered to have
critical impact.

CVE-2014-8121
Robin Hack discovered that the nss_files database did not
correctly implement enumeration interleaved with name-based or
ID-based lookups. This could cause the enumeration enter an
endless loop, leading to a denial of service.

CVE-2015-1781
Arjun Shankar discovered that the _r variants of host name
resolution functions (like gethostbyname_r), when performing DNS
name resolution, suffered from a buffer overflow if a misaligned
buffer was supplied by the applications, leading to a crash or,
potentially, arbitrary code execution. Most applications are not
affected by this vulnerability because they use aligned buffers.

CVE-2015-7547
The Google Security Team and Red Hat discovered that the eglibc
host name resolver function, getaddrinfo, when processing
AF_UNSPEC queries (for dual A/AAAA lookups), could mismanage its
internal buffers, leading to a stack-based buffer overflow and
arbitrary code execution. This vulnerability affects most
applications which perform host name resolution using getaddrinfo,
including system services.

Description truncated. Please see the references for more information.

While it is only necessary to ensure that all processes are not using
the old eglibc anymore, it is recommended to reboot the machines after
applying the security upgrade." );
	script_tag( name: "vuldetect", value: "This check tests the installed
software version using the apt package manager." );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(( res = isdpkgvuln( pkg: "eglibc-source", ver: "2.13-38+deb7u10", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "glibc-doc", ver: "2.13-38+deb7u10", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libc-bin", ver: "2.13-38+deb7u10", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libc-dev-bin", ver: "2.13-38+deb7u10", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libc0.1", ver: "2.13-38+deb7u10", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libc0.1-dbg", ver: "2.13-38+deb7u10", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libc0.1-dev", ver: "2.13-38+deb7u10", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libc0.1-dev-i386", ver: "2.13-38+deb7u10", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libc0.1-i386", ver: "2.13-38+deb7u10", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libc0.1-i686", ver: "2.13-38+deb7u10", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libc0.1-pic", ver: "2.13-38+deb7u10", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libc0.1-prof", ver: "2.13-38+deb7u10", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libc6", ver: "2.13-38+deb7u10", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libc6-amd64", ver: "2.13-38+deb7u10", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libc6-dbg", ver: "2.13-38+deb7u10", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libc6-dev", ver: "2.13-38+deb7u10", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libc6-dev-amd64", ver: "2.13-38+deb7u10", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libc6-dev-i386", ver: "2.13-38+deb7u10", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libc6-dev-mips64", ver: "2.13-38+deb7u10", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libc6-dev-mipsn32", ver: "2.13-38+deb7u10", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libc6-dev-ppc64", ver: "2.13-38+deb7u10", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libc6-dev-s390", ver: "2.13-38+deb7u10", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libc6-dev-s390x", ver: "2.13-38+deb7u10", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libc6-dev-sparc64", ver: "2.13-38+deb7u10", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libc6-i386", ver: "2.13-38+deb7u10", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libc6-i686", ver: "2.13-38+deb7u10", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libc6-loongson2f", ver: "2.13-38+deb7u10", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libc6-mips64", ver: "2.13-38+deb7u10", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libc6-mipsn32", ver: "2.13-38+deb7u10", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libc6-pic", ver: "2.13-38+deb7u10", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libc6-ppc64", ver: "2.13-38+deb7u10", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libc6-prof", ver: "2.13-38+deb7u10", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libc6-s390", ver: "2.13-38+deb7u10", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libc6-s390x", ver: "2.13-38+deb7u10", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libc6-sparc64", ver: "2.13-38+deb7u10", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libc6-xen", ver: "2.13-38+deb7u10", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libc6.1", ver: "2.13-38+deb7u10", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libc6.1-dbg", ver: "2.13-38+deb7u10", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libc6.1-dev", ver: "2.13-38+deb7u10", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libc6.1-pic", ver: "2.13-38+deb7u10", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libc6.1-prof", ver: "2.13-38+deb7u10", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "locales", ver: "2.13-38+deb7u10", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "locales-all", ver: "2.13-38+deb7u10", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "multiarch-support", ver: "2.13-38+deb7u10", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "nscd", ver: "2.13-38+deb7u10", rls: "DEB7" ) ) != NULL){
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

