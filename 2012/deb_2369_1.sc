if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.70688" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:N/A:N" );
	script_cve_id( "CVE-2011-2524" );
	script_version( "$Revision: 14275 $" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-18 15:39:45 +0100 (Mon, 18 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2012-02-11 03:14:57 -0500 (Sat, 11 Feb 2012)" );
	script_name( "Debian Security Advisory DSA 2369-1 (libsoup2.4)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2012 E-Soft Inc. http://www.securityspace.com" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB(5|6)" );
	script_xref( name: "URL", value: "https://secure1.securityspace.com/smysecure/catid.html?in=DSA%202369-1" );
	script_tag( name: "insight", value: "It was discovered that libsoup2.4, a HTTP library implementation in C, is
not properly validating input when processing requests made to SoupServer.
A remote attacker can exploit this flaw to access system files via a
directory traversal attack.

For the oldstable distribution (lenny), this problem has been fixed in
version 2.4.1-2+lenny1.

For the stable distribution (squeeze), this problem has been fixed in
version 2.30.2-1+squeeze1.

For the testing distribution (squeeze), this problem has been fixed in
version 2.34.3-1.

For the unstable distribution (sid), this problem has been fixed in
version 2.34.3-1." );
	script_tag( name: "solution", value: "We recommend that you upgrade your libsoup2.4 packages." );
	script_tag( name: "summary", value: "The remote host is missing an update to libsoup2.4
announced via advisory DSA 2369-1." );
	script_tag( name: "qod_type", value: "package" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(( res = isdpkgvuln( pkg: "libsoup2.4-1", ver: "2.4.1-2+lenny1", rls: "DEB5" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libsoup2.4-dev", ver: "2.4.1-2+lenny1", rls: "DEB5" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libsoup2.4-doc", ver: "2.4.1-2+lenny1", rls: "DEB5" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libsoup-gnome2.4-1", ver: "2.30.2-1+squeeze1", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libsoup-gnome2.4-dev", ver: "2.30.2-1+squeeze1", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libsoup2.4-1", ver: "2.30.2-1+squeeze1", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libsoup2.4-dbg", ver: "2.30.2-1+squeeze1", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libsoup2.4-dev", ver: "2.30.2-1+squeeze1", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libsoup2.4-doc", ver: "2.30.2-1+squeeze1", rls: "DEB6" ) ) != NULL){
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

