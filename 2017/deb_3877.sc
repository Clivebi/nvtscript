if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.703877" );
	script_version( "2021-09-14T14:01:45+0000" );
	script_cve_id( "CVE-2017-0376" );
	script_name( "Debian Security Advisory DSA 3877-1 (tor - security update)" );
	script_tag( name: "last_modification", value: "2021-09-14 14:01:45 +0000 (Tue, 14 Sep 2021)" );
	script_tag( name: "creation_date", value: "2017-06-10 00:00:00 +0200 (Sat, 10 Jun 2017)" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-10-03 00:03:00 +0000 (Thu, 03 Oct 2019)" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	script_xref( name: "URL", value: "http://www.debian.org/security/2017/dsa-3877.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2017 Greenbone Networks GmbH" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB(8|9)" );
	script_tag( name: "affected", value: "tor on Debian Linux" );
	script_tag( name: "solution", value: "For the stable distribution (jessie), this problem has been fixed in
version 0.2.5.14-1.

For the upcoming stable distribution (stretch), this problem will be
fixed in version 0.2.9.11-1~deb9u1.

For the unstable distribution (sid), this problem has been fixed in
version 0.2.9.11-1.

We recommend that you upgrade your tor packages." );
	script_tag( name: "summary", value: "It has been discovered that Tor, a connection-based low-latency
anonymous communication system, contain a flaw in the hidden service
code when receiving a BEGIN_DIR cell on a hidden service rendezvous
circuit. A remote attacker can take advantage of this flaw to cause a
hidden service to crash with an assertion failure (TROVE-2017-005)." );
	script_tag( name: "vuldetect", value: "This check tests the installed software version using the apt package manager." );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(( res = isdpkgvuln( pkg: "tor", ver: "0.2.5.14-1", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "tor-dbg", ver: "0.2.5.14-1", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "tor-geoipdb", ver: "0.2.5.14-1", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "tor", ver: "0.2.9.11-1~deb9u1", rls: "DEB9" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "tor-dbg", ver: "0.2.9.11-1~deb9u1", rls: "DEB9" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "tor-geoipdb", ver: "0.2.9.11-1~deb9u1", rls: "DEB9" ) ) != NULL){
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

