if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.71259" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_cve_id( "CVE-2012-0884", "CVE-2012-1165", "CVE-2012-2110", "CVE-2011-4619" );
	script_version( "$Revision: 14275 $" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-18 15:39:45 +0100 (Mon, 18 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2012-04-30 07:57:50 -0400 (Mon, 30 Apr 2012)" );
	script_name( "Debian Security Advisory DSA 2454-1 (openssl)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2012 E-Soft Inc. http://www.securityspace.com" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB6" );
	script_xref( name: "URL", value: "https://secure1.securityspace.com/smysecure/catid.html?in=DSA%202454-1" );
	script_tag( name: "insight", value: "Multiple vulnerabilities have been found in OpenSSL. The Common
Vulnerabilities and Exposures project identifies the following issues:

CVE-2012-0884

Ivan Nestlerode discovered a weakness in the CMS and PKCS #7
implementations that could allow an attacker to decrypt data
via a Million Message Attack (MMA).

CVE-2012-1165

It was discovered that a NULL pointer could be dereferenced
when parsing certain S/MIME messages, leading to denial of
service.

CVE-2012-2110

Tavis Ormandy, Google Security Team, discovered a vulnerability
in the way DER-encoded ASN.1 data is parsed that can result in
a heap overflow.


Additionally, the fix for CVE-2011-4619 has been updated to address an
issue with SGC handshakes.

For the stable distribution (squeeze), these problems have been fixed in
version 0.9.8o-4squeeze11.

For the testing distribution (wheezy), these problems will be fixed soon.

For the unstable distribution (sid), these problems have been fixed in
version 1.0.1a-1." );
	script_tag( name: "solution", value: "We recommend that you upgrade your openssl packages." );
	script_tag( name: "summary", value: "The remote host is missing an update to openssl
announced via advisory DSA 2454-1." );
	script_tag( name: "qod_type", value: "package" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(( res = isdpkgvuln( pkg: "libcrypto0.9.8-udeb", ver: "0.9.8o-4squeeze7", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libssl-dev", ver: "0.9.8o-4squeeze12", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libssl0.9.8", ver: "0.9.8o-4squeeze12", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libssl0.9.8-dbg", ver: "0.9.8o-4squeeze12", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "openssl", ver: "0.9.8o-4squeeze12", rls: "DEB6" ) ) != NULL){
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

