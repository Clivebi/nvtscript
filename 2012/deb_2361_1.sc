if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.70573" );
	script_tag( name: "cvss_base", value: "9.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:C/I:C/A:C" );
	script_cve_id( "CVE-2011-4000" );
	script_version( "$Revision: 14275 $" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-18 15:39:45 +0100 (Mon, 18 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2012-02-11 02:34:05 -0500 (Sat, 11 Feb 2012)" );
	script_name( "Debian Security Advisory DSA 2361-1 (chasen)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2012 E-Soft Inc. http://www.securityspace.com" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB(5|6)" );
	script_xref( name: "URL", value: "https://secure1.securityspace.com/smysecure/catid.html?in=DSA%202361-1" );
	script_tag( name: "insight", value: "It was discovered that ChaSen, a Japanese morphological analysis
system, contains a buffer overflow, potentially leading to arbitrary
code execution in programs using the library.

For the oldstable distribution (lenny), this problem has been fixed in
version 2.4.4-2+lenny2.

For the stable distribution (squeeze), this problem has been fixed in
version 2.4.4-11+squeeze2." );
	script_tag( name: "solution", value: "We recommend that you upgrade your chasen packages." );
	script_tag( name: "summary", value: "The remote host is missing an update to chasen
announced via advisory DSA 2361-1." );
	script_tag( name: "qod_type", value: "package" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(( res = isdpkgvuln( pkg: "chasen", ver: "2.4.4-2+lenny2", rls: "DEB5" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "chasen-dictutils", ver: "2.4.4-2+lenny2", rls: "DEB5" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libchasen-dev", ver: "2.4.4-2+lenny2", rls: "DEB5" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libchasen2", ver: "2.4.4-2+lenny2", rls: "DEB5" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "chasen", ver: "2.4.4-11+squeeze2", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "chasen-dictutils", ver: "2.4.4-11+squeeze2", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libchasen-dev", ver: "2.4.4-11+squeeze2", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libchasen2", ver: "2.4.4-11+squeeze2", rls: "DEB6" ) ) != NULL){
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

