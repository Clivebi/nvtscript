if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.71260" );
	script_cve_id( "CVE-2012-2112" );
	script_version( "$Revision: 14275 $" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-18 15:39:45 +0100 (Mon, 18 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2012-04-30 07:57:54 -0400 (Mon, 30 Apr 2012)" );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:P/A:N" );
	script_name( "Debian Security Advisory DSA 2455-1 (typo3-src)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2012 E-Soft Inc. http://www.securityspace.com" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB6" );
	script_xref( name: "URL", value: "https://secure1.securityspace.com/smysecure/catid.html?in=DSA%202455-1" );
	script_tag( name: "insight", value: "Helmut Hummel of the typo3 security team discovered that typo3, a web
content management system, is not properly sanitizing output of the
exception handler.  This allows an attacker to conduct cross-site
scripting attacks if either third-party extensions are installed that do
not sanitize this output on their own or in the presence of extensions
using the extbase MVC framework which accept objects to controller actions.


For the stable distribution (squeeze), this problem has been fixed in
version 4.3.9+dfsg1-1+squeeze4.

For the testing (wheezy) and unstable (sid) distributions, this problem
will be fixed soon." );
	script_tag( name: "solution", value: "We recommend that you upgrade your typo3-src packages." );
	script_tag( name: "summary", value: "The remote host is missing an update to typo3-src
announced via advisory DSA 2455-1." );
	script_tag( name: "qod_type", value: "package" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(( res = isdpkgvuln( pkg: "typo3", ver: "4.3.9+dfsg1-1+squeeze4", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "typo3-database", ver: "4.3.9+dfsg1-1+squeeze4", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "typo3-src-4.3", ver: "4.3.9+dfsg1-1+squeeze4", rls: "DEB6" ) ) != NULL){
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

