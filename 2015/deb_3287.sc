if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.703287" );
	script_version( "2021-09-20T13:38:59+0000" );
	script_cve_id( "CVE-2014-8176", "CVE-2015-1788", "CVE-2015-1789", "CVE-2015-1790", "CVE-2015-1791", "CVE-2015-1792", "CVE-2015-4000" );
	script_name( "Debian Security Advisory DSA 3287-1 (openssl - security update)" );
	script_tag( name: "last_modification", value: "2021-09-20 13:38:59 +0000 (Mon, 20 Sep 2021)" );
	script_tag( name: "creation_date", value: "2015-06-13 00:00:00 +0200 (Sat, 13 Jun 2015)" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	script_xref( name: "URL", value: "http://www.debian.org/security/2015/dsa-3287.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2015 Greenbone Networks GmbH" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB(7|9|8)" );
	script_tag( name: "affected", value: "openssl on Debian Linux" );
	script_tag( name: "solution", value: "For the oldstable distribution (wheezy), these problems have been fixed
in version 1.0.1e-2+deb7u17.

For the stable distribution (jessie), these problems have been fixed in
version 1.0.1k-3+deb8u1.

For the testing distribution (stretch), these problems have been fixed
in version 1.0.2b-1.

For the unstable distribution (sid), these problems have been fixed in
version 1.0.2b-1.

We recommend that you upgrade your openssl packages." );
	script_tag( name: "summary", value: "Multiple vulnerabilities were discovered in OpenSSL, a Secure Sockets
Layer toolkit.

CVE-2014-8176
Praveen Kariyanahalli, Ivan Fratric and Felix Groebert discovered
that an invalid memory free could be triggered when buffering DTLS
data. This could allow remote attackers to cause a denial of service
(crash) or potentially execute arbitrary code. This issue only
affected the oldstable distribution (wheezy).

CVE-2015-1788
Joseph Barr-Pixton discovered that an infinite loop could be triggered
due to incorrect handling of malformed ECParameters structures. This
could allow remote attackers to cause a denial of service.

CVE-2015-1789
Robert Swiecki and Hanno Bck discovered that the X509_cmp_time
function could read a few bytes out of bounds. This could allow remote
attackers to cause a denial of service (crash) via crafted
certificates and CRLs.

CVE-2015-1790
Michal Zalewski discovered that the PKCS#7 parsing code did not
properly handle missing content which could lead to a NULL pointer
dereference. This could allow remote attackers to cause a denial of
service (crash) via crafted ASN.1-encoded PKCS#7 blobs.

CVE-2015-1791
Emilia Ksper discovered that a race condition could occur due to
incorrect handling of NewSessionTicket in a multi-threaded client,
leading to a double free. This could allow remote attackers to cause
a denial of service (crash).

CVE-2015-1792
Johannes Bauer discovered that the CMS code could enter an infinite
loop when verifying a signedData message, if presented with an
unknown hash function OID. This could allow remote attackers to cause
a denial of service.

Additionally OpenSSL will now reject handshakes using DH parameters
shorter than 768 bits as a countermeasure against the Logjam attack
(CVE-2015-4000
)." );
	script_tag( name: "vuldetect", value: "This check tests the installed software version using the apt package manager." );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(( res = isdpkgvuln( pkg: "libcrypto1.0.0-udeb", ver: "1.0.1e-2+deb7u17", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libssl-dev", ver: "1.0.1e-2+deb7u17", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libssl-doc", ver: "1.0.1e-2+deb7u17", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libssl1.0.0", ver: "1.0.1e-2+deb7u17", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libssl1.0.0-dbg", ver: "1.0.1e-2+deb7u17", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "openssl", ver: "1.0.1e-2+deb7u17", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libcrypto1.0.0-udeb", ver: "1.0.2b-1", rls: "DEB9" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libssl-dev", ver: "1.0.2b-1", rls: "DEB9" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libssl-doc", ver: "1.0.2b-1", rls: "DEB9" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libssl1.0.0", ver: "1.0.2b-1", rls: "DEB9" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libssl1.0.0-dbg", ver: "1.0.2b-1", rls: "DEB9" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "openssl", ver: "1.0.2b-1", rls: "DEB9" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libcrypto1.0.0-udeb", ver: "1.0.1k-3+deb8u1", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libssl-dev", ver: "1.0.1k-3+deb8u1", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libssl-doc", ver: "1.0.1k-3+deb8u1", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libssl1.0.0", ver: "1.0.1k-3+deb8u1", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libssl1.0.0-dbg", ver: "1.0.1k-3+deb8u1", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "openssl", ver: "1.0.1k-3+deb8u1", rls: "DEB8" ) ) != NULL){
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

