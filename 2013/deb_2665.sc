if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.702665" );
	script_version( "2020-10-05T06:02:24+0000" );
	script_cve_id( "CVE-2012-2388", "CVE-2013-2944" );
	script_name( "Debian Security Advisory DSA 2665-1 (strongswan - authentication bypass)" );
	script_tag( name: "last_modification", value: "2020-10-05 06:02:24 +0000 (Mon, 05 Oct 2020)" );
	script_tag( name: "creation_date", value: "2013-04-30 00:00:00 +0200 (Tue, 30 Apr 2013)" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_xref( name: "URL", value: "http://www.debian.org/security/2013/dsa-2665.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2013 Greenbone Networks GmbH http://greenbone.net" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB(6|7)" );
	script_tag( name: "affected", value: "strongswan on Debian Linux" );
	script_tag( name: "solution", value: "For the stable distribution (squeeze), this problem has been fixed in
version 4.4.1-5.3.

For the testing distribution (wheezy), this problem has been fixed in
version 4.5.2-1.5+deb7u1.

For the unstable distribution (sid), this problem has been fixed in
version 4.6.4-7.

We recommend that you upgrade your strongswan packages." );
	script_tag( name: "summary", value: "Kevin Wojtysiak discovered a vulnerability in strongSwan, an IPsec
based VPN solution.

When using the OpenSSL plugin for ECDSA based authentication, an empty,
zeroed or otherwise invalid signature is handled as a legitimate one.
An attacker could use a forged signature to authenticate like a legitimate
user and gain access to the VPN (and everything protected by this).

While the issue looks like CVE-2012-2388

(RSA signature based authentication bypass), it is unrelated." );
	script_tag( name: "vuldetect", value: "This check tests the installed software version using the apt package manager." );
	script_tag( name: "qod_type", value: "package" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(( res = isdpkgvuln( pkg: "libstrongswan", ver: "4.4.1-5.3", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "strongswan", ver: "4.4.1-5.3", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "strongswan-dbg", ver: "4.4.1-5.3", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "strongswan-ikev1", ver: "4.4.1-5.3", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "strongswan-ikev2", ver: "4.4.1-5.3", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "strongswan-nm", ver: "4.4.1-5.3", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "strongswan-starter", ver: "4.4.1-5.3", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libstrongswan", ver: "4.5.2-1.5+deb7u1", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "strongswan", ver: "4.5.2-1.5+deb7u1", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "strongswan-dbg", ver: "4.5.2-1.5+deb7u1", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "strongswan-ikev1", ver: "4.5.2-1.5+deb7u1", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "strongswan-ikev2", ver: "4.5.2-1.5+deb7u1", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "strongswan-nm", ver: "4.5.2-1.5+deb7u1", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "strongswan-starter", ver: "4.5.2-1.5+deb7u1", rls: "DEB7" ) ) != NULL){
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

