if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.69987" );
	script_version( "$Revision: 14275 $" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-18 15:39:45 +0100 (Mon, 18 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2011-08-03 04:36:20 +0200 (Wed, 03 Aug 2011)" );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_cve_id( "CVE-2010-3077", "CVE-2010-3694" );
	script_name( "Debian Security Advisory DSA 2278-1 (horde3)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2011 E-Soft Inc. http://www.securityspace.com" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB(5|6|7)" );
	script_xref( name: "URL", value: "https://secure1.securityspace.com/smysecure/catid.html?in=DSA%202278-1" );
	script_tag( name: "insight", value: "It was discovered that horde3, the horde web application framework, is
prone to a cross-site scripting attack and a cross-site request forgery.

For the oldstable distribution (lenny), these problems have been fixed
in version 3.2.2+debian0-2+lenny3.

For the stable distribution (squeeze), these problems have been fixed in
version 3.3.8+debian0-2, which was already included in the squeeze
release.

For the testing distribution (wheezy) and the unstable distribution
(sid), these problems have been fixed in version 3.3.8+debian0-2." );
	script_tag( name: "solution", value: "We recommend that you upgrade your horde3 packages." );
	script_tag( name: "summary", value: "The remote host is missing an update to horde3
announced via advisory DSA 2278-1." );
	script_tag( name: "qod_type", value: "package" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(( res = isdpkgvuln( pkg: "horde3", ver: "3.2.2+debian0-2+lenny3", rls: "DEB5" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "horde3", ver: "3.3.8+debian0-2", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "horde3", ver: "3.3.8+debian0-2", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "pear-horde-channel", ver: "3.3.8+debian0-2", rls: "DEB7" ) ) != NULL){
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

