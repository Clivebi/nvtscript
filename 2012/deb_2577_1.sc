if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.72627" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_cve_id( "CVE-2012-4559", "CVE-2012-4561", "CVE-2012-4562" );
	script_version( "$Revision: 14275 $" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-18 15:39:45 +0100 (Mon, 18 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2012-12-04 11:43:00 -0500 (Tue, 04 Dec 2012)" );
	script_name( "Debian Security Advisory DSA 2577-1 (libssh)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2012 E-Soft Inc. http://www.securityspace.com" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB(6|7)" );
	script_xref( name: "URL", value: "https://secure1.securityspace.com/smysecure/catid.html?in=DSA%202577-1" );
	script_tag( name: "insight", value: "Multiple vulnerabilities were discovered in libssh by Florian Weimer and Xi
Wang:

CVE-2012-4559: multiple double free() flaws
CVE-2012-4561: multiple invalid free() flaws
CVE-2012-4562: multiple improper overflow checks

Those could lead to a denial of service by making an ssh client linked to
libssh crash, and maybe even arbitrary code execution.

For the stable distribution (squeeze), these problems have been fixed in
version 0.4.5-3+squeeze1.

For the testing distribution (wheezy), these problems have been fixed in
version 0.5.3-1.

For the unstable distribution (sid), these problems have been fixed in
version 0.5.3-1." );
	script_tag( name: "solution", value: "We recommend that you upgrade your libssh packages." );
	script_tag( name: "summary", value: "The remote host is missing an update to libssh
announced via advisory DSA 2577-1." );
	script_tag( name: "qod_type", value: "package" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(( res = isdpkgvuln( pkg: "libssh-4", ver: "0.4.5-3+squeeze1", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libssh-dbg", ver: "0.4.5-3+squeeze1", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libssh-dev", ver: "0.4.5-3+squeeze1", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libssh-doc", ver: "0.4.5-3+squeeze1", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libssh-4", ver: "0.5.3-1", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libssh-dbg", ver: "0.5.3-1", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libssh-dev", ver: "0.5.3-1", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libssh-doc", ver: "0.5.3-1", rls: "DEB7" ) ) != NULL){
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

