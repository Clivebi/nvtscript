if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.70567" );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_cve_id( "CVE-2011-3581" );
	script_version( "$Revision: 14275 $" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-18 15:39:45 +0100 (Mon, 18 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2012-02-11 02:31:49 -0500 (Sat, 11 Feb 2012)" );
	script_name( "Debian Security Advisory DSA 2353-1 (ldns)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2012 E-Soft Inc. http://www.securityspace.com" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB(5|6)" );
	script_xref( name: "URL", value: "https://secure1.securityspace.com/smysecure/catid.html?in=DSA%202353-1" );
	script_tag( name: "insight", value: "David Wheeler discovered a buffer overflow in ldns's code to parse
RR records, which could lead to the execution of arbitrary code.

For the oldstable distribution (lenny), this problem has been fixed in
version 1.4.0-1+lenny2.

For the stable distribution (squeeze), this problem has been fixed in
version 1.6.6-2+squeeze1.

For the unstable distribution (sid), this problem has been fixed in
version 1.6.11-1." );
	script_tag( name: "solution", value: "We recommend that you upgrade your ldns packages." );
	script_tag( name: "summary", value: "The remote host is missing an update to ldns
announced via advisory DSA 2353-1." );
	script_tag( name: "qod_type", value: "package" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(( res = isdpkgvuln( pkg: "ldnsutils", ver: "1.4.0-1+lenny1", rls: "DEB5" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libldns-dev", ver: "1.4.0-1+lenny1", rls: "DEB5" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libldns1", ver: "1.4.0-1+lenny1", rls: "DEB5" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "ldnsutils", ver: "1.6.6-2+squeeze1", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libldns-dev", ver: "1.6.6-2+squeeze1", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libldns1", ver: "1.6.6-2+squeeze1", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "python-ldns", ver: "1.6.6-2+squeeze1", rls: "DEB6" ) ) != NULL){
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

