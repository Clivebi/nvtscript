if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.891449" );
	script_version( "2021-06-16T02:00:28+0000" );
	script_cve_id( "CVE-2018-0732", "CVE-2018-0737" );
	script_name( "Debian LTS: Security Advisory for openssl (DLA-1449-1)" );
	script_tag( name: "last_modification", value: "2021-06-16 02:00:28 +0000 (Wed, 16 Jun 2021)" );
	script_tag( name: "creation_date", value: "2018-07-30 00:00:00 +0200 (Mon, 30 Jul 2018)" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-06-08 12:15:00 +0000 (Tue, 08 Jun 2021)" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	script_xref( name: "URL", value: "https://lists.debian.org/debian-lts-announce/2018/07/msg00043.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH http://greenbone.net" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB8" );
	script_tag( name: "affected", value: "openssl on Debian Linux" );
	script_tag( name: "solution", value: "For Debian 8 'Jessie', these problems have been fixed in version
1.0.1t-1+deb8u9.

We recommend that you upgrade your openssl packages." );
	script_tag( name: "summary", value: "Two issues were discovered in OpenSSL, the Secure Sockets Layer toolkit.

CVE-2018-0732

Denial of service by a malicious server that sends a very large
prime value to the client during TLS handshake.

CVE-2018-0737

Alejandro Cabrera Aldaya, Billy Brumley, Cesar Pereida Garcia and
Luis Manuel Alvarez Tapia discovered that the OpenSSL RSA Key
generation algorithm has been shown to be vulnerable to a cache
timing side channel attack. An attacker with sufficient access to
mount cache timing attacks during the RSA key generation process
could recover the private key." );
	script_tag( name: "vuldetect", value: "This check tests the installed software version using the apt package manager." );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(!isnull( res = isdpkgvuln( pkg: "libssl-dev", ver: "1.0.1t-1+deb8u9", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libssl-doc", ver: "1.0.1t-1+deb8u9", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libssl1.0.0", ver: "1.0.1t-1+deb8u9", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libssl1.0.0-dbg", ver: "1.0.1t-1+deb8u9", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "openssl", ver: "1.0.1t-1+deb8u9", rls: "DEB8" ) )){
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

