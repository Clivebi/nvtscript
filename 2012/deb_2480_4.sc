if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.72206" );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_version( "$Revision: 14275 $" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-18 15:39:45 +0100 (Mon, 18 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2012-09-19 03:27:39 -0400 (Wed, 19 Sep 2012)" );
	script_name( "Debian Security Advisory DSA 2480-4 (request-tracker3.8)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2012 E-Soft Inc. http://www.securityspace.com" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB6" );
	script_xref( name: "URL", value: "https://secure1.securityspace.com/smysecure/catid.html?in=DSA%202480-4" );
	script_tag( name: "insight", value: "The security updates for request-tracker3.8, DSA-2480-1, DSA-2480-2,
and DSA-2480-3, contained minor regressions. Namely:

  * The calendar popup page in Internet Explorer would be blocked by the
CSRF protection mechanism.

  * Search results pages could not be shared without saving, sharing, and
then loading the search.

  * rt-email-dashboards would fail with an error due to a call to an
undefined interp method.

Please note that if you run request-tracker3.8 under the Apache web
server, you must stop and start Apache manually.  The restart
mechanism is not recommended, especially when using mod_perl.

For the stable distribution (squeeze), this problem has been fixed in
version 3.8.8-7+squeeze5." );
	script_tag( name: "solution", value: "We recommend that you upgrade your request-tracker3.8 packages." );
	script_tag( name: "summary", value: "The remote host is missing an update to request-tracker3.8
announced via advisory DSA 2480-4." );
	script_tag( name: "qod_type", value: "package" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(( res = isdpkgvuln( pkg: "request-tracker3.8", ver: "3.8.8-7+squeeze5", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "rt3.8-apache2", ver: "3.8.8-7+squeeze5", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "rt3.8-clients", ver: "3.8.8-7+squeeze5", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "rt3.8-db-mysql", ver: "3.8.8-7+squeeze5", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "rt3.8-db-postgresql", ver: "3.8.8-7+squeeze5", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "rt3.8-db-sqlite", ver: "3.8.8-7+squeeze5", rls: "DEB6" ) ) != NULL){
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

