if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.703962" );
	script_version( "2021-09-15T12:01:38+0000" );
	script_cve_id( "CVE-2017-11185" );
	script_name( "Debian Security Advisory DSA 3962-1 (strongswan - security update)" );
	script_tag( name: "last_modification", value: "2021-09-15 12:01:38 +0000 (Wed, 15 Sep 2021)" );
	script_tag( name: "creation_date", value: "2017-09-03 00:00:00 +0200 (Sun, 03 Sep 2017)" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2018-08-13 21:47:00 +0000 (Mon, 13 Aug 2018)" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	script_xref( name: "URL", value: "http://www.debian.org/security/2017/dsa-3962.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2017 Greenbone Networks GmbH" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB(8|10|9)" );
	script_tag( name: "affected", value: "strongswan on Debian Linux" );
	script_tag( name: "solution", value: "For the oldstable distribution (jessie), this problem has been fixed
in version 5.2.1-6+deb8u5.

For the stable distribution (stretch), this problem has been fixed in
version 5.5.1-4+deb9u1.

For the testing distribution (buster), this problem has been fixed
in version 5.6.0-1.

For the unstable distribution (sid), this problem has been fixed in
version 5.6.0-1.

We recommend that you upgrade your strongswan packages." );
	script_tag( name: "summary", value: "A denial of service vulnerability was identified in strongSwan, an IKE/IPsec
suite, using Google's OSS-Fuzz fuzzing project.

The gmp plugin in strongSwan had insufficient input validation when verifying
RSA signatures. This coding error could lead to a null pointer dereference,
leading to process crash." );
	script_tag( name: "vuldetect", value: "This check tests the installed software version using the apt package manager." );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(( res = isdpkgvuln( pkg: "charon-cmd", ver: "5.2.1-6+deb8u5", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libcharon-extra-plugins", ver: "5.2.1-6+deb8u5", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libstrongswan", ver: "5.2.1-6+deb8u5", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libstrongswan-extra-plugins", ver: "5.2.1-6+deb8u5", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libstrongswan-standard-plugins", ver: "5.2.1-6+deb8u5", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "strongswan", ver: "5.2.1-6+deb8u5", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "strongswan-charon", ver: "5.2.1-6+deb8u5", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "strongswan-dbg", ver: "5.2.1-6+deb8u5", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "strongswan-ike", ver: "5.2.1-6+deb8u5", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "strongswan-ikev1", ver: "5.2.1-6+deb8u5", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "strongswan-ikev2", ver: "5.2.1-6+deb8u5", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "strongswan-libcharon", ver: "5.2.1-6+deb8u5", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "strongswan-nm", ver: "5.2.1-6+deb8u5", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "strongswan-starter", ver: "5.2.1-6+deb8u5", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "charon-cmd", ver: "5.6.0-1", rls: "DEB10" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "charon-systemd", ver: "5.6.0-1", rls: "DEB10" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libcharon-extra-plugins", ver: "5.6.0-1", rls: "DEB10" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libstrongswan", ver: "5.6.0-1", rls: "DEB10" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libstrongswan-extra-plugins", ver: "5.6.0-1", rls: "DEB10" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libstrongswan-standard-plugins", ver: "5.6.0-1", rls: "DEB10" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "strongswan", ver: "5.6.0-1", rls: "DEB10" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "strongswan-charon", ver: "5.6.0-1", rls: "DEB10" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "strongswan-ike", ver: "5.6.0-1", rls: "DEB10" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "strongswan-ikev1", ver: "5.6.0-1", rls: "DEB10" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "strongswan-ikev2", ver: "5.6.0-1", rls: "DEB10" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "strongswan-libcharon", ver: "5.6.0-1", rls: "DEB10" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "strongswan-nm", ver: "5.6.0-1", rls: "DEB10" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "strongswan-pki", ver: "5.6.0-1", rls: "DEB10" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "strongswan-scepclient", ver: "5.6.0-1", rls: "DEB10" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "strongswan-starter", ver: "5.6.0-1", rls: "DEB10" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "strongswan-swanctl", ver: "5.6.0-1", rls: "DEB10" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "charon-cmd", ver: "5.5.1-4+deb9u1", rls: "DEB9" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "charon-systemd", ver: "5.5.1-4+deb9u1", rls: "DEB9" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libcharon-extra-plugins", ver: "5.5.1-4+deb9u1", rls: "DEB9" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libstrongswan", ver: "5.5.1-4+deb9u1", rls: "DEB9" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libstrongswan-extra-plugins", ver: "5.5.1-4+deb9u1", rls: "DEB9" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libstrongswan-standard-plugins", ver: "5.5.1-4+deb9u1", rls: "DEB9" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "strongswan", ver: "5.5.1-4+deb9u1", rls: "DEB9" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "strongswan-charon", ver: "5.5.1-4+deb9u1", rls: "DEB9" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "strongswan-ike", ver: "5.5.1-4+deb9u1", rls: "DEB9" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "strongswan-ikev1", ver: "5.5.1-4+deb9u1", rls: "DEB9" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "strongswan-ikev2", ver: "5.5.1-4+deb9u1", rls: "DEB9" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "strongswan-libcharon", ver: "5.5.1-4+deb9u1", rls: "DEB9" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "strongswan-nm", ver: "5.5.1-4+deb9u1", rls: "DEB9" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "strongswan-pki", ver: "5.5.1-4+deb9u1", rls: "DEB9" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "strongswan-scepclient", ver: "5.5.1-4+deb9u1", rls: "DEB9" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "strongswan-starter", ver: "5.5.1-4+deb9u1", rls: "DEB9" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "strongswan-swanctl", ver: "5.5.1-4+deb9u1", rls: "DEB9" ) ) != NULL){
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

