if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.702626" );
	script_version( "2020-10-05T06:02:24+0000" );
	script_cve_id( "CVE-2012-4929", "CVE-2009-3555" );
	script_name( "Debian Security Advisory DSA 2626-1 (lighttpd - several issues)" );
	script_tag( name: "last_modification", value: "2020-10-05 06:02:24 +0000 (Mon, 05 Oct 2020)" );
	script_tag( name: "creation_date", value: "2013-02-17 00:00:00 +0100 (Sun, 17 Feb 2013)" );
	script_tag( name: "cvss_base", value: "5.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:P/A:P" );
	script_xref( name: "URL", value: "http://www.debian.org/security/2013/dsa-2626.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2013 Greenbone Networks GmbH http://greenbone.net" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB(6|7)" );
	script_tag( name: "affected", value: "lighttpd on Debian Linux" );
	script_tag( name: "solution", value: "For the stable distribution (squeeze), these problems have been fixed in
version 1.4.28-2+squeeze1.2.

For the testing distribution (wheezy), and the unstable distribution (sid)
these problems have been fixed in version 1.4.30-1.

We recommend that you upgrade your lighttpd packages." );
	script_tag( name: "summary", value: "Several vulnerabilities were discovered in the TLS/SSL protocol. This
update addresses these protocol vulnerabilities in lighttpd.

CVE-2009-3555
Marsh Ray, Steve Dispensa, and Martin Rex discovered that the TLS
and SSLv3 protocols do not properly associate renegotiation
handshakes with an existing connection, which allows man-in-the-middle
attackers to insert data into HTTPS sessions. This issue is solved
in lighttpd by disabling client initiated renegotiation by default.

Those users that do actually need such renegotiations, can re-enable
them via the new ssl.disable-client-renegotiation
parameter.

CVE-2012-4929Juliano Rizzo and Thai Duong discovered a weakness in the TLS/SSL
protocol when using compression. This side channel attack, dubbed
CRIME
, allows eavesdroppers to gather information to recover the
original plaintext in the protocol. This update disables compression." );
	script_tag( name: "vuldetect", value: "This check tests the installed software version using the apt package manager." );
	script_tag( name: "qod_type", value: "package" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(( res = isdpkgvuln( pkg: "lighttpd", ver: "1.4.28-2+squeeze1.2", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "lighttpd-doc", ver: "1.4.28-2+squeeze1.2", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "lighttpd-mod-cml", ver: "1.4.28-2+squeeze1.2", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "lighttpd-mod-magnet", ver: "1.4.28-2+squeeze1.2", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "lighttpd-mod-mysql-vhost", ver: "1.4.28-2+squeeze1.2", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "lighttpd-mod-trigger-b4-dl", ver: "1.4.28-2+squeeze1.2", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "lighttpd-mod-webdav", ver: "1.4.28-2+squeeze1.2", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "lighttpd", ver: "1.4.30-1", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "lighttpd-doc", ver: "1.4.30-1", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "lighttpd-mod-cml", ver: "1.4.30-1", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "lighttpd-mod-magnet", ver: "1.4.30-1", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "lighttpd-mod-mysql-vhost", ver: "1.4.30-1", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "lighttpd-mod-trigger-b4-dl", ver: "1.4.30-1", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "lighttpd-mod-webdav", ver: "1.4.30-1", rls: "DEB7" ) ) != NULL){
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

