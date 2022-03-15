if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.71251" );
	script_cve_id( "CVE-2012-1173" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_tag( name: "cvss_base", value: "6.8" );
	script_version( "$Revision: 14275 $" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-18 15:39:45 +0100 (Mon, 18 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2012-04-30 07:55:56 -0400 (Mon, 30 Apr 2012)" );
	script_name( "Debian Security Advisory DSA 2447-1 (tiff)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2012 E-Soft Inc. http://www.securityspace.com" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB6" );
	script_xref( name: "URL", value: "https://secure1.securityspace.com/smysecure/catid.html?in=DSA%202447-1" );
	script_tag( name: "insight", value: "Alexander Gavrun discovered an integer overflow in the TIFF library
in the parsing of the TileSize entry, which could result in the execution
of arbitrary code if a malformed image is opened.

For the stable distribution (squeeze), this problem has been fixed in
version 3.9.4-5+squeeze4.

For the unstable distribution (sid), this problem will be fixed soon." );
	script_tag( name: "solution", value: "We recommend that you upgrade your tiff packages." );
	script_tag( name: "summary", value: "The remote host is missing an update to tiff
announced via advisory DSA 2447-1." );
	script_tag( name: "qod_type", value: "package" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(( res = isdpkgvuln( pkg: "libtiff-doc", ver: "3.9.4-5+squeeze4", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libtiff-opengl", ver: "3.9.4-5+squeeze4", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libtiff-tools", ver: "3.9.4-5+squeeze4", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libtiff4", ver: "3.9.4-5+squeeze4", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libtiff4-dev", ver: "3.9.4-5+squeeze4", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libtiffxx0c2", ver: "3.9.4-5+squeeze4", rls: "DEB6" ) ) != NULL){
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

