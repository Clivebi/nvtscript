if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.72532" );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_cve_id( "CVE-2012-4447" );
	script_version( "$Revision: 14275 $" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-18 15:39:45 +0100 (Mon, 18 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2012-10-29 10:13:51 -0400 (Mon, 29 Oct 2012)" );
	script_name( "Debian Security Advisory DSA 2561-1 (tiff)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2012 E-Soft Inc. http://www.securityspace.com" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB(6|7)" );
	script_xref( name: "URL", value: "https://secure1.securityspace.com/smysecure/catid.html?in=DSA%202561-1" );
	script_tag( name: "insight", value: "It was discovered that a buffer overflow in libtiff's parsing of files
using PixarLog compression could lead to the execution of arbitrary
code.

For the stable distribution (squeeze), this problem has been fixed in
version 3.9.4-5+squeeze6.

For the testing distribution (wheezy) and the unstable distribution
sid), this problem has been fixed in version 3.9.6-9 of the tiff3
source package and in version 4.0.2-4 of the tiff source package." );
	script_tag( name: "solution", value: "We recommend that you upgrade your tiff packages." );
	script_tag( name: "summary", value: "The remote host is missing an update to tiff
announced via advisory DSA 2561-1." );
	script_tag( name: "qod_type", value: "package" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(( res = isdpkgvuln( pkg: "libtiff-doc", ver: "3.9.4-5+squeeze6", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libtiff-opengl", ver: "3.9.4-5+squeeze6", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libtiff-tools", ver: "3.9.4-5+squeeze6", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libtiff4", ver: "3.9.4-5+squeeze6", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libtiff4-dev", ver: "3.9.4-5+squeeze6", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libtiffxx0c2", ver: "3.9.4-5+squeeze6", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libtiff-doc", ver: "4.0.2-4", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libtiff-opengl", ver: "4.0.2-4", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libtiff-tools", ver: "4.0.2-4", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libtiff5", ver: "4.0.2-4", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libtiff5-alt-dev", ver: "4.0.2-4", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libtiff5-dev", ver: "4.0.2-4", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libtiffxx5", ver: "4.0.2-4", rls: "DEB7" ) ) != NULL){
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

