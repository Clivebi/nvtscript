if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.703967" );
	script_version( "2021-09-15T09:01:43+0000" );
	script_cve_id( "CVE-2017-14032" );
	script_name( "Debian Security Advisory DSA 3967-1 (mbedtls - security update)" );
	script_tag( name: "last_modification", value: "2021-09-15 09:01:43 +0000 (Wed, 15 Sep 2021)" );
	script_tag( name: "creation_date", value: "2017-09-08 00:00:00 +0200 (Fri, 08 Sep 2017)" );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2017-11-08 02:29:00 +0000 (Wed, 08 Nov 2017)" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	script_xref( name: "URL", value: "http://www.debian.org/security/2017/dsa-3967.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2017 Greenbone Networks GmbH" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB(10|9)" );
	script_tag( name: "affected", value: "mbedtls on Debian Linux" );
	script_tag( name: "solution", value: "For the stable distribution (stretch), this problem has been fixed in
version 2.4.2-1+deb9u1.

For the testing distribution (buster), this problem has been fixed
in version 2.6.0-1.

For the unstable distribution (sid), this problem has been fixed in
version 2.6.0-1.

We recommend that you upgrade your mbedtls packages." );
	script_tag( name: "summary", value: "An authentication bypass vulnerability was discovered in mbed TLS, a
lightweight crypto and SSL/TLS library, when the authentication mode is
configured as optional
. A remote attacker can take advantage of this
flaw to mount a man-in-the-middle attack and impersonate an intended
peer via an X.509 certificate chain with many intermediates." );
	script_tag( name: "vuldetect", value: "This check tests the installed software version using the apt package manager." );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(( res = isdpkgvuln( pkg: "libmbedcrypto0", ver: "2.6.0-1", rls: "DEB10" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libmbedtls-dev", ver: "2.6.0-1", rls: "DEB10" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libmbedtls-doc", ver: "2.6.0-1", rls: "DEB10" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libmbedtls10", ver: "2.6.0-1", rls: "DEB10" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libmbedx509-0", ver: "2.6.0-1", rls: "DEB10" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libmbedcrypto0", ver: "2.4.2-1+deb9u1", rls: "DEB9" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libmbedtls-dev", ver: "2.4.2-1+deb9u1", rls: "DEB9" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libmbedtls-doc", ver: "2.4.2-1+deb9u1", rls: "DEB9" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libmbedtls10", ver: "2.4.2-1+deb9u1", rls: "DEB9" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libmbedx509-0", ver: "2.4.2-1+deb9u1", rls: "DEB9" ) ) != NULL){
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

