if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.703053" );
	script_version( "$Revision: 14302 $" );
	script_cve_id( "CVE-2014-3513", "CVE-2014-3566", "CVE-2014-3567", "CVE-2014-3568" );
	script_name( "Debian Security Advisory DSA 3053-1 (openssl - security update)" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-19 09:28:48 +0100 (Tue, 19 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2014-10-16 00:00:00 +0200 (Thu, 16 Oct 2014)" );
	script_tag( name: "cvss_base", value: "7.1" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:N/A:C" );
	script_xref( name: "URL", value: "http://www.debian.org/security/2014/dsa-3053.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2014 Greenbone Networks GmbH http://greenbone.net" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB7" );
	script_tag( name: "affected", value: "openssl on Debian Linux" );
	script_tag( name: "solution", value: "For the stable distribution (wheezy), these problems have been fixed in
version 1.0.1e-2+deb7u13.

For the unstable distribution (sid), these problems have been fixed in
version 1.0.1j-1.

We recommend that you upgrade your openssl packages." );
	script_tag( name: "summary", value: "Several vulnerabilities have been found in OpenSSL, the Secure Sockets
Layer library and toolkit.

CVE-2014-3513
A memory leak flaw was found in the way OpenSSL parsed the DTLS Secure
Real-time Transport Protocol (SRTP) extension data. A remote attacker
could send multiple specially crafted handshake messages to exhaust
all available memory of an SSL/TLS or DTLS server.

CVE-2014-3566 ('POODLE')
A flaw was found in the way SSL 3.0 handled padding bytes when
decrypting messages encrypted using block ciphers in cipher block
chaining (CBC) mode. This flaw allows a man-in-the-middle (MITM)
attacker to decrypt a selected byte of a cipher text in as few as 256
tries if they are able to force a victim application to repeatedly send
the same data over newly created SSL 3.0 connections.

This update adds support for Fallback SCSV to mitigate this issue.

CVE-2014-3567
A memory leak flaw was found in the way an OpenSSL handled failed
session ticket integrity checks. A remote attacker could exhaust all
available memory of an SSL/TLS or DTLS server by sending a large number
of invalid session tickets to that server.

CVE-2014-3568
When OpenSSL is configured with 'no-ssl3' as a build option, servers
could accept and complete a SSL 3.0 handshake, and clients could be
configured to send them." );
	script_tag( name: "vuldetect", value: "This check tests the installed software version using the apt package manager." );
	script_tag( name: "qod_type", value: "package" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(( res = isdpkgvuln( pkg: "libssl-dev", ver: "1.0.1e-2+deb7u13", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libssl-doc", ver: "1.0.1e-2+deb7u13", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libssl1.0.0", ver: "1.0.1e-2+deb7u13", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libssl1.0.0-dbg", ver: "1.0.1e-2+deb7u13", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "openssl", ver: "1.0.1e-2+deb7u13", rls: "DEB7" ) ) != NULL){
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

