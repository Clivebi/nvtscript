if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.703511" );
	script_version( "$Revision: 14275 $" );
	script_cve_id( "CVE-2016-1285", "CVE-2016-1286" );
	script_name( "Debian Security Advisory DSA 3511-1 (bind9 - security update)" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-18 15:39:45 +0100 (Mon, 18 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2016-03-09 00:00:00 +0100 (Wed, 09 Mar 2016)" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:P" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	script_xref( name: "URL", value: "http://www.debian.org/security/2016/dsa-3511.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2016 Greenbone Networks GmbH http://greenbone.net" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB(7|8)" );
	script_tag( name: "affected", value: "bind9 on Debian Linux" );
	script_tag( name: "solution", value: "For the oldstable distribution (wheezy),
these problems have been fixed in version 1:9.8.4.dfsg.P1-6+nmu2+deb7u10.

For the stable distribution (jessie), these problems have been fixed in
version 1:9.9.5.dfsg-9+deb8u6.

For the testing (stretch) and unstable (sid) distributions, these
problems will be fixed soon.

We recommend that you upgrade your bind9 packages." );
	script_tag( name: "summary", value: "Two vulnerabilities have been
discovered in ISC's BIND DNS server.

CVE-2016-1285
A maliciously crafted rdnc, a way to remotely administer a BIND server,
operation can cause named to crash, resulting in denial of service.

CVE-2016-1286
An error parsing DNAME resource records can cause named to crash,
resulting in denial of service." );
	script_tag( name: "vuldetect", value: "This check tests the installed software
version using the apt package manager." );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(( res = isdpkgvuln( pkg: "bind9", ver: "1:9.8.4.dfsg.P1-6+nmu2+deb7u10", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "bind9-doc", ver: "1:9.8.4.dfsg.P1-6+nmu2+deb7u10", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "bind9-host", ver: "1:9.8.4.dfsg.P1-6+nmu2+deb7u10", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "bind9utils", ver: "1:9.8.4.dfsg.P1-6+nmu2+deb7u10", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "dnsutils", ver: "1:9.8.4.dfsg.P1-6+nmu2+deb7u10", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "host", ver: "1:9.8.4.dfsg.P1-6+nmu2+deb7u10", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libbind-dev", ver: "1:9.8.4.dfsg.P1-6+nmu2+deb7u10", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libbind9-80", ver: "1:9.8.4.dfsg.P1-6+nmu2+deb7u10", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libdns88", ver: "1:9.8.4.dfsg.P1-6+nmu2+deb7u10", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libisc84", ver: "1:9.8.4.dfsg.P1-6+nmu2+deb7u10", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libisccc80", ver: "1:9.8.4.dfsg.P1-6+nmu2+deb7u10", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libisccfg82", ver: "1:9.8.4.dfsg.P1-6+nmu2+deb7u10", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "liblwres80", ver: "1:9.8.4.dfsg.P1-6+nmu2+deb7u10", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "lwresd", ver: "1:9.8.4.dfsg.P1-6+nmu2+deb7u10", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "bind9", ver: "1:9.9.5.dfsg-9+deb8u6", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "bind9-doc", ver: "1:9.9.5.dfsg-9+deb8u6", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "bind9-host", ver: "1:9.9.5.dfsg-9+deb8u6", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "bind9utils", ver: "1:9.9.5.dfsg-9+deb8u6", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "dnsutils", ver: "1:9.9.5.dfsg-9+deb8u6", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "host", ver: "1:9.9.5.dfsg-9+deb8u6", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libbind-dev", ver: "1:9.9.5.dfsg-9+deb8u6", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libbind-export-dev", ver: "1:9.9.5.dfsg-9+deb8u6", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libbind9-90", ver: "1:9.9.5.dfsg-9+deb8u6", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libdns-export100", ver: "1:9.9.5.dfsg-9+deb8u6", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libdns100", ver: "1:9.9.5.dfsg-9+deb8u6", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libirs-export91", ver: "1:9.9.5.dfsg-9+deb8u6", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libisc-export95", ver: "1:9.9.5.dfsg-9+deb8u6", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libisc95", ver: "1:9.9.5.dfsg-9+deb8u6", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libisccc90", ver: "1:9.9.5.dfsg-9+deb8u6", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libisccfg-export90", ver: "1:9.9.5.dfsg-9+deb8u6", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libisccfg90", ver: "1:9.9.5.dfsg-9+deb8u6", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "liblwres90", ver: "1:9.9.5.dfsg-9+deb8u6", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "lwresd", ver: "1:9.9.5.dfsg-9+deb8u6", rls: "DEB8" ) ) != NULL){
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

