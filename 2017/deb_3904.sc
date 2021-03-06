if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.703904" );
	script_version( "2021-09-17T10:01:50+0000" );
	script_cve_id( "CVE-2017-3142", "CVE-2017-3143" );
	script_name( "Debian Security Advisory DSA 3904-1 (bind9 - security update)" );
	script_tag( name: "last_modification", value: "2021-09-17 10:01:50 +0000 (Fri, 17 Sep 2021)" );
	script_tag( name: "creation_date", value: "2017-07-08 00:00:00 +0200 (Sat, 08 Jul 2017)" );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:N/A:N" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-08-30 17:15:00 +0000 (Fri, 30 Aug 2019)" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	script_xref( name: "URL", value: "http://www.debian.org/security/2017/dsa-3904.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2017 Greenbone Networks GmbH" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB(8|9)" );
	script_tag( name: "affected", value: "bind9 on Debian Linux" );
	script_tag( name: "solution", value: "For the oldstable distribution (jessie), these problems have been fixed
in version 1:9.9.5.dfsg-9+deb8u12.

For the stable distribution (stretch), these problems have been fixed in
version 1:9.10.3.dfsg.P4-12.3+deb9u1.

We recommend that you upgrade your bind9 packages." );
	script_tag( name: "summary", value: "Clement Berthaux from Synaktiv discovered two vulnerabilities in BIND, a DNS
server implementation. They allow an attacker to bypass TSIG authentication by
sending crafted DNS packets to a server.

CVE-2017-3142
An attacker who is able to send and receive messages to an authoritative
DNS server and who has knowledge of a valid TSIG key name may be able to
circumvent TSIG authentication of AXFR requests via a carefully constructed
request packet. A server that relies solely on TSIG keys for protection
with no other ACL protection could be manipulated into:

providing an AXFR of a zone to an unauthorized recipientaccepting bogus NOTIFY packetsCVE-2017-3143
An attacker who is able to send and receive messages to an authoritative
DNS server and who has knowledge of a valid TSIG key name for the zone and
service being targeted may be able to manipulate BIND into accepting an
unauthorized dynamic update." );
	script_tag( name: "vuldetect", value: "This check tests the installed software version using the apt package manager." );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(( res = isdpkgvuln( pkg: "bind9", ver: "1:9.9.5.dfsg-9+deb8u12", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "bind9-doc", ver: "1:9.9.5.dfsg-9+deb8u12", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "bind9-host", ver: "1:9.9.5.dfsg-9+deb8u12", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "bind9utils", ver: "1:9.9.5.dfsg-9+deb8u12", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "dnsutils", ver: "1:9.9.5.dfsg-9+deb8u12", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "host", ver: "1:9.9.5.dfsg-9+deb8u12", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libbind-dev", ver: "1:9.9.5.dfsg-9+deb8u12", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libbind-export-dev", ver: "1:9.9.5.dfsg-9+deb8u12", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libbind9-90", ver: "1:9.9.5.dfsg-9+deb8u12", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libdns-export100", ver: "1:9.9.5.dfsg-9+deb8u12", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libdns100", ver: "1:9.9.5.dfsg-9+deb8u12", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libirs-export91", ver: "1:9.9.5.dfsg-9+deb8u12", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libisc-export95", ver: "1:9.9.5.dfsg-9+deb8u12", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libisc95", ver: "1:9.9.5.dfsg-9+deb8u12", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libisccc90", ver: "1:9.9.5.dfsg-9+deb8u12", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libisccfg-export90", ver: "1:9.9.5.dfsg-9+deb8u12", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libisccfg90", ver: "1:9.9.5.dfsg-9+deb8u12", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "liblwres90", ver: "1:9.9.5.dfsg-9+deb8u12", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "lwresd", ver: "1:9.9.5.dfsg-9+deb8u12", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "bind9", ver: "1:9.10.3.dfsg.P4-12.3+deb9u1", rls: "DEB9" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "bind9-doc", ver: "1:9.10.3.dfsg.P4-12.3+deb9u1", rls: "DEB9" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "bind9-host", ver: "1:9.10.3.dfsg.P4-12.3+deb9u1", rls: "DEB9" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "bind9utils", ver: "1:9.10.3.dfsg.P4-12.3+deb9u1", rls: "DEB9" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "dnsutils", ver: "1:9.10.3.dfsg.P4-12.3+deb9u1", rls: "DEB9" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "host", ver: "1:9.10.3.dfsg.P4-12.3+deb9u1", rls: "DEB9" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libbind-dev", ver: "1:9.10.3.dfsg.P4-12.3+deb9u1", rls: "DEB9" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libbind-export-dev", ver: "1:9.10.3.dfsg.P4-12.3+deb9u1", rls: "DEB9" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libbind9-140", ver: "1:9.10.3.dfsg.P4-12.3+deb9u1", rls: "DEB9" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libdns-export162", ver: "1:9.10.3.dfsg.P4-12.3+deb9u1", rls: "DEB9" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libdns162", ver: "1:9.10.3.dfsg.P4-12.3+deb9u1", rls: "DEB9" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libirs-export141", ver: "1:9.10.3.dfsg.P4-12.3+deb9u1", rls: "DEB9" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libirs141", ver: "1:9.10.3.dfsg.P4-12.3+deb9u1", rls: "DEB9" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libisc-export160", ver: "1:9.10.3.dfsg.P4-12.3+deb9u1", rls: "DEB9" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libisc160", ver: "1:9.10.3.dfsg.P4-12.3+deb9u1", rls: "DEB9" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libisccc-export140", ver: "1:9.10.3.dfsg.P4-12.3+deb9u1", rls: "DEB9" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libisccc140", ver: "1:9.10.3.dfsg.P4-12.3+deb9u1", rls: "DEB9" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libisccfg-export140", ver: "1:9.10.3.dfsg.P4-12.3+deb9u1", rls: "DEB9" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libisccfg140", ver: "1:9.10.3.dfsg.P4-12.3+deb9u1", rls: "DEB9" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "liblwres141", ver: "1:9.10.3.dfsg.P4-12.3+deb9u1", rls: "DEB9" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "lwresd", ver: "1:9.10.3.dfsg.P4-12.3+deb9u1", rls: "DEB9" ) ) != NULL){
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

