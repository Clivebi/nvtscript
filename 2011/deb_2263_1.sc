if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.69969" );
	script_version( "$Revision: 14275 $" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-18 15:39:45 +0100 (Mon, 18 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2011-08-03 04:36:20 +0200 (Wed, 03 Aug 2011)" );
	script_tag( name: "cvss_base", value: "9.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:C/I:C/A:C" );
	script_name( "Debian Security Advisory DSA 2263-1 (movabletype-opensource)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2011 E-Soft Inc. http://www.securityspace.com" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB6" );
	script_xref( name: "URL", value: "https://secure1.securityspace.com/smysecure/catid.html?in=DSA%202263-1" );
	script_tag( name: "insight", value: "It was discovered that Movable Type, a weblog publishing system,
contains several security vulnerabilities:

A remote attacker could execute arbitrary code in a logged-in users'
web browser.

A remote attacker could read or modify the contents in the system
under certain circumstances.

For the oldstable distribution (lenny), no update is available at this
time.

For the stable distribution (squeeze), these problems have been fixed in
version 4.3.5+dfsg-2+squeeze2.

For the testing distribution (wheezy) and for the unstable
distribution (sid), these problems have been fixed in version
4.3.6.1+dfsg-1." );
	script_tag( name: "solution", value: "We recommend that you upgrade your movabletype-opensource packages." );
	script_tag( name: "summary", value: "The remote host is missing an update to movabletype-opensource
announced via advisory DSA 2263-1." );
	script_tag( name: "qod_type", value: "package" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(( res = isdpkgvuln( pkg: "movabletype-opensource", ver: "4.3.5+dfsg-2+squeeze2", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "movabletype-plugin-core", ver: "4.3.5+dfsg-2+squeeze2", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "movabletype-plugin-zemanta", ver: "4.3.5+dfsg-2+squeeze2", rls: "DEB6" ) ) != NULL){
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

