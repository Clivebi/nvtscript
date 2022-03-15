if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.70556" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_version( "$Revision: 14275 $" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-18 15:39:45 +0100 (Mon, 18 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2012-02-11 02:29:08 -0500 (Sat, 11 Feb 2012)" );
	script_name( "Debian Security Advisory DSA 2343-1 (openssl)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2012 E-Soft Inc. http://www.securityspace.com" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB(5|6)" );
	script_xref( name: "URL", value: "https://secure1.securityspace.com/smysecure/catid.html?in=DSA%202343-1" );
	script_tag( name: "insight", value: "Several weak certificates were issued by Malaysian intermediate CA
Digicert Sdn. Bhd. This event, along with other issues, has lead to
Entrust Inc. and Verizon Cybertrust to revoke the CA's cross-signed
certificates.

This update to OpenSSL, a Secure Sockets Layer toolkit, reflects this
decision by marking Digicert Sdn. Bhd.'s certificates as revoked.

For the oldstable distribution (lenny), this problem has been fixed in
version 0.9.8g-15+lenny14.

For the stable distribution (squeeze), this problem has been fixed in
version 0.9.8o-4squeeze4.

For the testing distribution (wheezy), this problem will be fixed soon.

For the unstable distribution (sid), this problem has been fixed in
version 1.0.0e-2.1." );
	script_tag( name: "solution", value: "We recommend that you upgrade your openssl packages." );
	script_tag( name: "summary", value: "The remote host is missing an update to openssl
announced via advisory DSA 2343-1." );
	script_tag( name: "qod_type", value: "package" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(( res = isdpkgvuln( pkg: "libcrypto0.9.8-udeb", ver: "0.9.8g-15+lenny13", rls: "DEB5" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libssl-dev", ver: "0.9.8g-15+lenny14", rls: "DEB5" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libssl0.9.8", ver: "0.9.8g-15+lenny14", rls: "DEB5" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libssl0.9.8-dbg", ver: "0.9.8g-15+lenny14", rls: "DEB5" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "openssl", ver: "0.9.8g-15+lenny14", rls: "DEB5" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libcrypto0.9.8-udeb", ver: "0.9.8o-4squeeze4", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libssl-dev", ver: "0.9.8o-4squeeze4", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libssl0.9.8", ver: "0.9.8o-4squeeze4", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libssl0.9.8-dbg", ver: "0.9.8o-4squeeze4", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "openssl", ver: "0.9.8o-4squeeze4", rls: "DEB6" ) ) != NULL){
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
