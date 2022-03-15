if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.70549" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_cve_id( "CVE-2011-4075", "CVE-2011-4074" );
	script_version( "$Revision: 14275 $" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-18 15:39:45 +0100 (Mon, 18 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2012-02-11 02:27:28 -0500 (Sat, 11 Feb 2012)" );
	script_name( "Debian Security Advisory DSA 2333-1 (phpldapadmin)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2012 E-Soft Inc. http://www.securityspace.com" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB(5|6)" );
	script_xref( name: "URL", value: "https://secure1.securityspace.com/smysecure/catid.html?in=DSA%202333-1" );
	script_tag( name: "insight", value: "Two vulnerabilities have been discovered in phpldapadmin, a web based
interface for administering LDAP servers. The Common Vulnerabilities and
Exposures project identifies the following problems:

CVE-2011-4074

Input appended to the URL in cmd.php (when cmd is set to _debug) is
not properly sanitised before being returned to the user. This can be
exploited to execute arbitrary HTML and script code in a user's browser
session in context of an affected site.

CVE-2011-4075

Input passed to the orderby parameter in cmd.php (when cmd is set to
query_engine, query is set to none, and search is set to e.g.
1) is not properly sanitised in lib/functions.php before being used in a
create_function() function call. This can be exploited to inject and
execute arbitrary PHP code.


For the oldstable distribution (lenny), these problems have been fixed in
version 1.1.0.5-6+lenny2.

For the stable distribution (squeeze), these problems have been fixed in
version 1.2.0.5-2+squeeze1.

For the testing distribution (wheezy), these problems will be fixed soon.

For the unstable distribution (sid), these problems have been fixed in
version 1.2.0.5-2.1." );
	script_tag( name: "solution", value: "We recommend that you upgrade your phpldapadmin packages." );
	script_tag( name: "summary", value: "The remote host is missing an update to phpldapadmin
announced via advisory DSA 2333-1." );
	script_tag( name: "qod_type", value: "package" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(( res = isdpkgvuln( pkg: "phpldapadmin", ver: "1.1.0.5-6+lenny2", rls: "DEB5" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "phpldapadmin", ver: "1.2.0.5-2+squeeze1", rls: "DEB6" ) ) != NULL){
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

