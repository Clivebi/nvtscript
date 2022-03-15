if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.69966" );
	script_version( "$Revision: 14275 $" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-18 15:39:45 +0100 (Mon, 18 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2011-08-03 04:36:20 +0200 (Wed, 03 Aug 2011)" );
	script_cve_id( "CVE-2011-1409" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:P/A:N" );
	script_name( "Debian Security Advisory DSA 2259-1 (fex)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2011 E-Soft Inc. http://www.securityspace.com" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB6" );
	script_xref( name: "URL", value: "https://secure1.securityspace.com/smysecure/catid.html?in=DSA%202259-1" );
	script_tag( name: "insight", value: "It was discovered that fex, a web service for transferring very large,
files, is not properly validating authentication IDs.  While the service
properly validates existing authentication IDs, an attacker who is not
specifying any authentication ID at all, can bypass the authentication
procedure.


The oldstable distribution (lenny) does not include fex.

For the stable distribution (squeeze), this problem has been fixed in
version 20100208+debian1-1+squeeze1.

For the testing distribution (wheezy), this problem will be fixed soon.

For the unstable distribution (sid), this problem has been fixed in
version 20110610-1." );
	script_tag( name: "solution", value: "We recommend that you upgrade your fex packages." );
	script_tag( name: "summary", value: "The remote host is missing an update to fex
announced via advisory DSA 2259-1." );
	script_tag( name: "qod_type", value: "package" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(( res = isdpkgvuln( pkg: "fex", ver: "20100208+debian1-1+squeeze1", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "fex-utils", ver: "20100208+debian1-1+squeeze1", rls: "DEB6" ) ) != NULL){
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

