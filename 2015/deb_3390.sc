if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.703390" );
	script_version( "$Revision: 14278 $" );
	script_cve_id( "CVE-2015-7835" );
	script_name( "Debian Security Advisory DSA 3390-1 (xen - security update)" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-18 15:47:26 +0100 (Mon, 18 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2015-11-02 00:00:00 +0100 (Mon, 02 Nov 2015)" );
	script_tag( name: "cvss_base", value: "7.2" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:L/Au:N/C:C/I:C/A:C" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	script_xref( name: "URL", value: "http://www.debian.org/security/2015/dsa-3390.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2015 Greenbone Networks GmbH http://greenbone.net" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB(7|8)" );
	script_tag( name: "affected", value: "xen on Debian Linux" );
	script_tag( name: "solution", value: "For the oldstable distribution (wheezy),
this problem has been fixed in version 4.1.4-3+deb7u9.

For the stable distribution (jessie), this problem has been fixed in
version 4.4.1-9+deb8u2.

We recommend that you upgrade your xen packages." );
	script_tag( name: "summary", value: "It was discovered that the code to
validate level 2 page table entries is bypassed when certain conditions are
satisfied. A malicious PV guest administrator can take advantage of this flaw
to gain privileges via a crafted superpage mapping." );
	script_tag( name: "vuldetect", value: "This check tests the installed
software version using the apt package manager." );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(( res = isdpkgvuln( pkg: "libxen-4.1", ver: "4.1.4-3+deb7u9", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libxen-dev", ver: "4.1.4-3+deb7u9", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libxen-ocaml", ver: "4.1.4-3+deb7u9", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libxen-ocaml-dev", ver: "4.1.4-3+deb7u9", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libxenstore3.0", ver: "4.1.4-3+deb7u9", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "xen-docs-4.1", ver: "4.1.4-3+deb7u9", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "xen-hypervisor-4.1-amd64", ver: "4.1.4-3+deb7u9", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "xen-hypervisor-4.1-i386", ver: "4.1.4-3+deb7u9", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "xen-system-amd64", ver: "4.1.4-3+deb7u9", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "xen-system-i386", ver: "4.1.4-3+deb7u9", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "xen-utils-4.1", ver: "4.1.4-3+deb7u9", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "xen-utils-common", ver: "4.1.4-3+deb7u9", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "xenstore-utils", ver: "4.1.4-3+deb7u9", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libxen-4.4", ver: "4.4.1-9+deb8u2", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libxen-dev", ver: "4.4.1-9+deb8u2", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libxenstore3.0", ver: "4.4.1-9+deb8u2", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "xen-hypervisor-4.4-amd64", ver: "4.4.1-9+deb8u2", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "xen-hypervisor-4.4-arm64", ver: "4.4.1-9+deb8u2", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "xen-hypervisor-4.4-armhf", ver: "4.4.1-9+deb8u2", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "xen-system-amd64", ver: "4.4.1-9+deb8u2", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "xen-system-arm64", ver: "4.4.1-9+deb8u2", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "xen-system-armhf", ver: "4.4.1-9+deb8u2", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "xen-utils-4.4", ver: "4.4.1-9+deb8u2", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "xen-utils-common", ver: "4.4.1-9+deb8u2", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "xenstore-utils", ver: "4.4.1-9+deb8u2", rls: "DEB8" ) ) != NULL){
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

