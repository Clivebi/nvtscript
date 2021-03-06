if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.71353" );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_cve_id( "CVE-2012-2333" );
	script_version( "$Revision: 14275 $" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-18 15:39:45 +0100 (Mon, 18 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2012-05-31 11:51:33 -0400 (Thu, 31 May 2012)" );
	script_name( "Debian Security Advisory DSA 2475-1 (openssl)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2012 E-Soft Inc. http://www.securityspace.com" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB(6|7)" );
	script_xref( name: "URL", value: "https://secure1.securityspace.com/smysecure/catid.html?in=DSA%202475-1" );
	script_tag( name: "insight", value: "It was discovered that openssl did not correctly handle explicit
Initialization Vectors for CBC encryption modes, as used in TLS 1.1,
1.2, and DTLS. An incorrect calculation would lead to an integer
underflow and incorrect memory access, causing denial of service
(application crash.)

For the stable distribution (squeeze), this problem has been fixed in
version 0.9.8o-4squeeze13.

For the testing distribution (wheezy), and the unstable distribution
(sid), this problem has been fixed in version 1.0.1c-1." );
	script_tag( name: "solution", value: "We recommend that you upgrade your openssl packages." );
	script_tag( name: "summary", value: "The remote host is missing an update to openssl
announced via advisory DSA 2475-1." );
	script_tag( name: "qod_type", value: "package" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(( res = isdpkgvuln( pkg: "libcrypto0.9.8-udeb", ver: "0.9.8o-4squeeze12", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libssl-dev", ver: "0.9.8o-4squeeze13", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libssl0.9.8", ver: "0.9.8o-4squeeze13", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libssl0.9.8-dbg", ver: "0.9.8o-4squeeze13", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "openssl", ver: "0.9.8o-4squeeze13", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libcrypto1.0.0-udeb", ver: "1.0.1c-1", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libssl-dev", ver: "1.0.1c-1", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libssl-doc", ver: "1.0.1c-1", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libssl1.0.0", ver: "1.0.1c-1", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libssl1.0.0-dbg", ver: "1.0.1c-1", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "openssl", ver: "1.0.1c-1", rls: "DEB7" ) ) != NULL){
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

