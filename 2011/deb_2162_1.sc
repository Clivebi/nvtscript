if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.68997" );
	script_version( "$Revision: 14275 $" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-18 15:39:45 +0100 (Mon, 18 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2011-03-07 16:04:02 +0100 (Mon, 07 Mar 2011)" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:P" );
	script_cve_id( "CVE-2011-0014" );
	script_name( "Debian Security Advisory DSA 2162-1 (openssl)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2011 E-Soft Inc. http://www.securityspace.com" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB(6|7)" );
	script_xref( name: "URL", value: "https://secure1.securityspace.com/smysecure/catid.html?in=DSA%202162-1" );
	script_tag( name: "insight", value: "Neel Mehta discovered that an incorrectly formatted ClientHello handshake
message could cause OpenSSL to parse past the end of the message.  This
allows an attacker to crash an application using OpenSSL by triggering
an invalid memory access.  Additionally, some applications may be vulnerable
to expose contents of a parsed OCSP nonce extension.

Packages in the oldstable distribution (lenny) are not affected by this
problem.

For the stable distribution (squeeze), this problem has been fixed in
version 0.9.8o-4squeeze1.

For the testing distribution (wheezy), this problem has been fixed in
version 0.9.8o-5.

For the unstable distribution (sid), this problem has been fixed in
version 0.9.8o-5." );
	script_tag( name: "solution", value: "We recommend that you upgrade your invalid memory access packages." );
	script_tag( name: "summary", value: "The remote host is missing an update to openssl
announced via advisory DSA 2162-1." );
	script_tag( name: "qod_type", value: "package" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(( res = isdpkgvuln( pkg: "libcrypto0.9.8-udeb", ver: "0.9.8o-4squeeze1", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libssl-dev", ver: "0.9.8o-4squeeze1", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libssl0.9.8", ver: "0.9.8o-4squeeze1", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libssl0.9.8-dbg", ver: "0.9.8o-4squeeze1", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "openssl", ver: "0.9.8o-4squeeze1", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libcrypto0.9.8-udeb", ver: "0.9.8o-5", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libssl-dev", ver: "0.9.8o-5", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libssl0.9.8", ver: "0.9.8o-5", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libssl0.9.8-dbg", ver: "0.9.8o-5", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "openssl", ver: "0.9.8o-5", rls: "DEB7" ) ) != NULL){
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

