if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.72442" );
	script_tag( name: "cvss_base", value: "10.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:C/A:C" );
	script_cve_id( "CVE-2012-1970", "CVE-2012-1972", "CVE-2012-1973", "CVE-2012-1974", "CVE-2012-1975", "CVE-2012-1976", "CVE-2012-3959", "CVE-2012-3962", "CVE-2012-3969", "CVE-2012-3972", "CVE-2012-3978" );
	script_version( "$Revision: 14275 $" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-18 15:39:45 +0100 (Mon, 18 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2012-10-03 11:10:13 -0400 (Wed, 03 Oct 2012)" );
	script_name( "Debian Security Advisory DSA 2554-1 (iceape)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2012 E-Soft Inc. http://www.securityspace.com" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB(6|7)" );
	script_xref( name: "URL", value: "https://secure1.securityspace.com/smysecure/catid.html?in=DSA%202554-1" );
	script_tag( name: "insight", value: "Several vulnerabilities have been discovered in Iceape, an internet suite based
on Seamonkey.

The reported vulnerabilities could lead to the execution of arbitrary
code or the bypass of content-loading restrictions via the location
object.

For the stable distribution (squeeze), these problems have been fixed in
version 2.0.11-15.

For the testing distribution (wheezy), these problems have been fixed in
version 2.7.7-1.

For the unstable distribution (sid), these problems have been fixed in
version 2.7.7-1." );
	script_tag( name: "solution", value: "We recommend that you upgrade your iceape packages." );
	script_tag( name: "summary", value: "The remote host is missing an update to iceape
announced via advisory DSA 2554-1." );
	script_tag( name: "qod_type", value: "package" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(( res = isdpkgvuln( pkg: "iceape", ver: "2.0.11-15", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "iceape-browser", ver: "2.0.11-15", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "iceape-chatzilla", ver: "2.0.11-15", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "iceape-dbg", ver: "2.0.11-15", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "iceape-dev", ver: "2.0.11-15", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "iceape-mailnews", ver: "2.0.11-15", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "iceape", ver: "2.7.7-1", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "iceape-browser", ver: "2.7.7-1", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "iceape-chatzilla", ver: "2.7.7-1", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "iceape-dbg", ver: "2.7.7-1", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "iceape-l10n-all", ver: "2.7.7-1", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "iceape-l10n-be", ver: "2.7.7-1", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "iceape-l10n-ca", ver: "2.7.7-1", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "iceape-l10n-cs", ver: "2.7.7-1", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "iceape-l10n-de", ver: "2.7.7-1", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "iceape-l10n-en-gb", ver: "2.7.7-1", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "iceape-l10n-es-ar", ver: "2.7.7-1", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "iceape-l10n-es-es", ver: "2.7.7-1", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "iceape-l10n-fi", ver: "2.7.7-1", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "iceape-l10n-fr", ver: "2.7.7-1", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "iceape-l10n-gl", ver: "2.7.7-1", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "iceape-l10n-hu", ver: "2.7.7-1", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "iceape-l10n-it", ver: "2.7.7-1", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "iceape-l10n-ja", ver: "2.7.7-1", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "iceape-l10n-lt", ver: "2.7.7-1", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "iceape-l10n-nb-no", ver: "2.7.7-1", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "iceape-l10n-nl", ver: "2.7.7-1", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "iceape-l10n-pl", ver: "2.7.7-1", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "iceape-l10n-pt-pt", ver: "2.7.7-1", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "iceape-l10n-ru", ver: "2.7.7-1", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "iceape-l10n-sk", ver: "2.7.7-1", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "iceape-l10n-sv-se", ver: "2.7.7-1", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "iceape-l10n-tr", ver: "2.7.7-1", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "iceape-l10n-zh-cn", ver: "2.7.7-1", rls: "DEB7" ) ) != NULL){
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

