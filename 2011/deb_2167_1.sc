if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.69000" );
	script_version( "2020-10-27T15:01:28+0000" );
	script_tag( name: "last_modification", value: "2020-10-27 15:01:28 +0000 (Tue, 27 Oct 2020)" );
	script_tag( name: "creation_date", value: "2011-03-07 16:04:02 +0100 (Mon, 07 Mar 2011)" );
	script_tag( name: "cvss_base", value: "6.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:S/C:P/I:P/A:P" );
	script_cve_id( "CVE-2011-0987" );
	script_name( "Debian Security Advisory DSA 2167-1 (phpmyadmin)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2011 E-Soft Inc. http://www.securityspace.com" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB(5|6|7)" );
	script_xref( name: "URL", value: "https://secure1.securityspace.com/smysecure/catid.html?in=DSA%202167-1" );
	script_tag( name: "insight", value: "It was discovered that phpMyAdmin, a tool to administer MySQL over
the web, when the bookmarks feature is enabled, allowed to create a
bookmarked query which would be executed unintentionally by other users.

For the oldstable distribution (lenny), this problem has been fixed in
version 4:2.11.8.1-5+lenny8.

For the stable distribution (squeeze), this problem has been fixed in
version 4:3.3.7-5.

For the testing distribution (wheezy) and unstable distribution (sid),
this problem has been fixed in version 4:3.3.9.2-1." );
	script_tag( name: "solution", value: "We recommend that you upgrade your phpmyadmin packages." );
	script_tag( name: "summary", value: "The remote host is missing an update to phpmyadmin
announced via advisory DSA 2167-1." );
	script_tag( name: "qod_type", value: "package" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(( res = isdpkgvuln( pkg: "phpmyadmin", ver: "4:2.11.8.1-5+lenny8", rls: "DEB5" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "phpmyadmin", ver: "4:3.3.7-5", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "phpmyadmin", ver: "4:3.3.9.2-1", rls: "DEB7" ) ) != NULL){
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

