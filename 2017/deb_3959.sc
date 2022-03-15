if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.703959" );
	script_version( "2021-09-17T08:01:48+0000" );
	script_cve_id( "CVE-2017-0379" );
	script_name( "Debian Security Advisory DSA 3959-1 (libgcrypt20 - security update)" );
	script_tag( name: "last_modification", value: "2021-09-17 08:01:48 +0000 (Fri, 17 Sep 2021)" );
	script_tag( name: "creation_date", value: "2017-08-29 00:00:00 +0200 (Tue, 29 Aug 2017)" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:N/A:N" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-01-16 19:29:00 +0000 (Wed, 16 Jan 2019)" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	script_xref( name: "URL", value: "http://www.debian.org/security/2017/dsa-3959.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2017 Greenbone Networks GmbH" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB9" );
	script_tag( name: "affected", value: "libgcrypt20 on Debian Linux" );
	script_tag( name: "solution", value: "For the stable distribution (stretch), this problem has been fixed in
version 1.7.6-2+deb9u2.

For the unstable distribution (sid), this problem has been fixed in
version 1.7.9-1.

We recommend that you upgrade your libgcrypt20 packages." );
	script_tag( name: "summary", value: "Daniel Genkin, Luke Valenta and Yuval Yarom discovered that Libgcrypt
is prone to a local side-channel attack against the ECDH encryption with
Curve25519, allowing recovery of the private key." );
	script_tag( name: "vuldetect", value: "This check tests the installed software version using the apt package manager." );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(( res = isdpkgvuln( pkg: "libgcrypt-mingw-w64-dev", ver: "1.7.6-2+deb9u2", rls: "DEB9" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libgcrypt11-dev", ver: "1.7.6-2+deb9u2", rls: "DEB9" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libgcrypt20", ver: "1.7.6-2+deb9u2", rls: "DEB9" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libgcrypt20-dev", ver: "1.7.6-2+deb9u2", rls: "DEB9" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libgcrypt20-doc", ver: "1.7.6-2+deb9u2", rls: "DEB9" ) ) != NULL){
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

