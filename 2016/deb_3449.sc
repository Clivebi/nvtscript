if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.703449" );
	script_version( "2021-09-20T08:01:57+0000" );
	script_cve_id( "CVE-2015-8704" );
	script_name( "Debian Security Advisory DSA 3449-1 (bind9 - security update)" );
	script_tag( name: "last_modification", value: "2021-09-20 08:01:57 +0000 (Mon, 20 Sep 2021)" );
	script_tag( name: "creation_date", value: "2016-01-19 00:00:00 +0100 (Tue, 19 Jan 2016)" );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:S/C:N/I:N/A:C" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2018-10-30 16:27:00 +0000 (Tue, 30 Oct 2018)" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	script_xref( name: "URL", value: "http://www.debian.org/security/2016/dsa-3449.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2016 Greenbone Networks GmbH" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB(8|7)" );
	script_tag( name: "affected", value: "bind9 on Debian Linux" );
	script_tag( name: "solution", value: "For the oldstable distribution (wheezy),
this problem has been fixed in version 1:9.8.4.dfsg.P1-6+nmu2+deb7u9.

For the stable distribution (jessie), this problem has been fixed in
version 1:9.9.5.dfsg-9+deb8u5.

We recommend that you upgrade your bind9 packages." );
	script_tag( name: "summary", value: "It was discovered that specific APL RR
data could trigger an INSIST failure in apl_42.c and cause the BIND DNS server to
exit, leading to a denial-of-service." );
	script_tag( name: "vuldetect", value: "This check tests the installed software
version using the apt package manager." );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(( res = isdpkgvuln( pkg: "bind9", ver: "1:9.9.5.dfsg-9+deb8u5", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "bind9-doc", ver: "1:9.9.5.dfsg-9+deb8u5", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "bind9-host", ver: "1:9.9.5.dfsg-9+deb8u5", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "bind9utils", ver: "1:9.9.5.dfsg-9+deb8u5", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "dnsutils", ver: "1:9.9.5.dfsg-9+deb8u5", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "host", ver: "1:9.9.5.dfsg-9+deb8u5", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libbind-dev", ver: "1:9.9.5.dfsg-9+deb8u5", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libbind-export-dev", ver: "1:9.9.5.dfsg-9+deb8u5", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libbind9-90", ver: "1:9.9.5.dfsg-9+deb8u5", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libdns-export100", ver: "1:9.9.5.dfsg-9+deb8u5", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libdns100", ver: "1:9.9.5.dfsg-9+deb8u5", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libirs-export91", ver: "1:9.9.5.dfsg-9+deb8u5", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libisc-export95", ver: "1:9.9.5.dfsg-9+deb8u5", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libisc95", ver: "1:9.9.5.dfsg-9+deb8u5", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libisccc90", ver: "1:9.9.5.dfsg-9+deb8u5", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libisccfg-export90", ver: "1:9.9.5.dfsg-9+deb8u5", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libisccfg90", ver: "1:9.9.5.dfsg-9+deb8u5", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "liblwres90", ver: "1:9.9.5.dfsg-9+deb8u5", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "lwresd", ver: "1:9.9.5.dfsg-9+deb8u5", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "bind9", ver: "1:9.8.4.dfsg.P1-6+nmu2+deb7u9", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "bind9-doc", ver: "1:9.8.4.dfsg.P1-6+nmu2+deb7u9", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "bind9-host", ver: "1:9.8.4.dfsg.P1-6+nmu2+deb7u9", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "bind9utils", ver: "1:9.8.4.dfsg.P1-6+nmu2+deb7u9", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "dnsutils", ver: "1:9.8.4.dfsg.P1-6+nmu2+deb7u9", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "host", ver: "1:9.8.4.dfsg.P1-6+nmu2+deb7u9", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libbind-dev", ver: "1:9.8.4.dfsg.P1-6+nmu2+deb7u9", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libbind9-80", ver: "1:9.8.4.dfsg.P1-6+nmu2+deb7u9", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libdns88", ver: "1:9.8.4.dfsg.P1-6+nmu2+deb7u9", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libisc84", ver: "1:9.8.4.dfsg.P1-6+nmu2+deb7u9", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libisccc80", ver: "1:9.8.4.dfsg.P1-6+nmu2+deb7u9", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libisccfg82", ver: "1:9.8.4.dfsg.P1-6+nmu2+deb7u9", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "liblwres80", ver: "1:9.8.4.dfsg.P1-6+nmu2+deb7u9", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "lwresd", ver: "1:9.8.4.dfsg.P1-6+nmu2+deb7u9", rls: "DEB7" ) ) != NULL){
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

