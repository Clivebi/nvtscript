if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.69957" );
	script_version( "$Revision: 14275 $" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-18 15:39:45 +0100 (Mon, 18 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2011-08-03 04:36:20 +0200 (Wed, 03 Aug 2011)" );
	script_cve_id( "CVE-2011-1756" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:P" );
	script_name( "Debian Security Advisory DSA 2250-1 (citadel)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2011 E-Soft Inc. http://www.securityspace.com" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB(5|6)" );
	script_xref( name: "URL", value: "https://secure1.securityspace.com/smysecure/catid.html?in=DSA%202250-1" );
	script_tag( name: "insight", value: "Wouter Coekaerts discovered that the jabber server component of citadel,
a complete and feature-rich groupware server, is vulnerable to the so-called
billion laughs attack because it does not prevent entity expansion on
received data.  This allows an attacker to perform denial of service
attacks against the service by sending specially crafted XML data to it.


For the oldstable distribution (lenny), this problem has been fixed in
version 7.37-8+lenny1.

For the stable distribution (squeeze), this problem has been fixed in
version 7.83-2squeeze2.

For the testing (wheezy) and unstable(sid) distributions,
this problem will be fixed soon." );
	script_tag( name: "solution", value: "We recommend that you upgrade your citadel packages." );
	script_tag( name: "summary", value: "The remote host is missing an update to citadel
announced via advisory DSA 2250-1." );
	script_tag( name: "qod_type", value: "package" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(( res = isdpkgvuln( pkg: "citadel-client", ver: "7.37-8+lenny1", rls: "DEB5" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "citadel-common", ver: "7.37-8+lenny1", rls: "DEB5" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "citadel-doc", ver: "7.37-8+lenny1", rls: "DEB5" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "citadel-mta", ver: "7.37-8+lenny1", rls: "DEB5" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "citadel-server", ver: "7.37-8+lenny1", rls: "DEB5" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "citadel-suite", ver: "7.37-8+lenny1", rls: "DEB5" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "citadel-client", ver: "7.83-2squeeze2", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "citadel-dbg", ver: "7.83-2squeeze2", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "citadel-doc", ver: "7.83-2squeeze2", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "citadel-mta", ver: "7.83-2squeeze2", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "citadel-server", ver: "7.83-2squeeze2", rls: "DEB6" ) ) != NULL){
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

