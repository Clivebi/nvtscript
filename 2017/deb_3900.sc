if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.703900" );
	script_version( "2021-09-13T14:16:31+0000" );
	script_cve_id( "CVE-2017-7479", "CVE-2017-7508", "CVE-2017-7520", "CVE-2017-7521" );
	script_name( "Debian Security Advisory DSA 3900-1 (openvpn - security update)" );
	script_tag( name: "last_modification", value: "2021-09-13 14:16:31 +0000 (Mon, 13 Sep 2021)" );
	script_tag( name: "creation_date", value: "2017-06-27 00:00:00 +0200 (Tue, 27 Jun 2017)" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-10-03 00:03:00 +0000 (Thu, 03 Oct 2019)" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	script_xref( name: "URL", value: "http://www.debian.org/security/2017/dsa-3900.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2017 Greenbone Networks GmbH" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB(8|9|10)" );
	script_tag( name: "affected", value: "openvpn on Debian Linux" );
	script_tag( name: "solution", value: "For the oldstable distribution (jessie), these problems have been fixed
in version 2.3.4-5+deb8u2.

For the stable distribution (stretch), these problems have been fixed in
version 2.4.0-6+deb9u1.

For the testing distribution (buster), these problems have been fixed
in version 2.4.3-1.

For the unstable distribution (sid), these problems have been fixed in
version 2.4.3-1.

We recommend that you upgrade your openvpn packages." );
	script_tag( name: "summary", value: "Several issues were discovered in openvpn, a virtual private network
application.

CVE-2017-7479
It was discovered that openvpn did not properly handle the
rollover of packet identifiers. This would allow an authenticated
remote attacker to cause a denial-of-service via application
crash.

CVE-2017-7508
Guido Vranken discovered that openvpn did not properly handle
specific malformed IPv6 packets. This would allow a remote
attacker to cause a denial-of-service via application crash.

CVE-2017-7520
Guido Vranken discovered that openvpn did not properly handle
clients connecting to an HTTP proxy with NTLMv2
authentication. This would allow a remote attacker to cause a
denial-of-service via application crash, or potentially leak
sensitive information like the user's proxy password.

CVE-2017-7521
Guido Vranken discovered that openvpn did not properly handle
some x509 extensions. This would allow a remote attacker to cause
a denial-of-service via application crash." );
	script_tag( name: "vuldetect", value: "This check tests the installed software version using the apt package manager." );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(( res = isdpkgvuln( pkg: "openvpn", ver: "2.3.4-5+deb8u2", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "openvpn", ver: "2.4.0-6+deb9u1", rls: "DEB9" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "openvpn", ver: "2.4.3-1", rls: "DEB10" ) ) != NULL){
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

