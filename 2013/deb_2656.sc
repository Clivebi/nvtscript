if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.702656" );
	script_version( "2020-10-05T06:02:24+0000" );
	script_cve_id( "CVE-2013-2266" );
	script_name( "Debian Security Advisory DSA 2656-1 (bind9 - denial of service)" );
	script_tag( name: "last_modification", value: "2020-10-05 06:02:24 +0000 (Mon, 05 Oct 2020)" );
	script_tag( name: "creation_date", value: "2013-03-30 00:00:00 +0100 (Sat, 30 Mar 2013)" );
	script_tag( name: "cvss_base", value: "7.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:C" );
	script_xref( name: "URL", value: "http://www.debian.org/security/2013/dsa-2656.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2013 Greenbone Networks GmbH http://greenbone.net" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB(6|7)" );
	script_tag( name: "affected", value: "bind9 on Debian Linux" );
	script_tag( name: "solution", value: "For the stable distribution (squeeze), this problem has been fixed in
version 1:9.7.3.dfsg-1~squeeze10.

For the testing distribution (wheezy), this problem has been fixed in
version 1:9.8.4.dfsg.P1-6+nmu1.

For the unstable distribution (sid), this problem has been fixed in
version 1:9.8.4.dfsg.P1-6+nmu1.

We recommend that you upgrade your bind9 packages." );
	script_tag( name: "summary", value: "Matthew Horsfall of Dyn, Inc. discovered that BIND, a DNS server, is
prone to a denial of service vulnerability. A remote attacker could use
this flaw to send a specially-crafted DNS query to named that, when
processed, would cause named to use an excessive amount of memory, or
possibly crash." );
	script_tag( name: "vuldetect", value: "This check tests the installed software version using the apt package manager." );
	script_tag( name: "qod_type", value: "package" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(( res = isdpkgvuln( pkg: "bind9", ver: "1:9.7.3.dfsg-1~squeeze10", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "bind9-doc", ver: "1:9.7.3.dfsg-1~squeeze10", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "bind9-host", ver: "1:9.7.3.dfsg-1~squeeze10", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "bind9utils", ver: "1:9.7.3.dfsg-1~squeeze10", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "dnsutils", ver: "1:9.7.3.dfsg-1~squeeze10", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "host", ver: "1:9.7.3.dfsg-1~squeeze10", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libbind-dev", ver: "1:9.7.3.dfsg-1~squeeze10", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libbind9-60", ver: "1:9.7.3.dfsg-1~squeeze10", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libdns69", ver: "1:9.7.3.dfsg-1~squeeze10", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libisc62", ver: "1:9.7.3.dfsg-1~squeeze10", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libisccc60", ver: "1:9.7.3.dfsg-1~squeeze10", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libisccfg62", ver: "1:9.7.3.dfsg-1~squeeze10", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "liblwres60", ver: "1:9.7.3.dfsg-1~squeeze10", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "lwresd", ver: "1:9.7.3.dfsg-1~squeeze10", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "bind9", ver: "1:9.8.4.dfsg.P1-6+nmu1", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "bind9-doc", ver: "1:9.8.4.dfsg.P1-6+nmu1", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "bind9-host", ver: "1:9.8.4.dfsg.P1-6+nmu1", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "bind9utils", ver: "1:9.8.4.dfsg.P1-6+nmu1", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "dnsutils", ver: "1:9.8.4.dfsg.P1-6+nmu1", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "host", ver: "1:9.8.4.dfsg.P1-6+nmu1", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libbind-dev", ver: "1:9.8.4.dfsg.P1-6+nmu1", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libbind9-80", ver: "1:9.8.4.dfsg.P1-6+nmu1", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libdns88", ver: "1:9.8.4.dfsg.P1-6+nmu1", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libisc84", ver: "1:9.8.4.dfsg.P1-6+nmu1", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libisccc80", ver: "1:9.8.4.dfsg.P1-6+nmu1", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libisccfg82", ver: "1:9.8.4.dfsg.P1-6+nmu1", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "liblwres80", ver: "1:9.8.4.dfsg.P1-6+nmu1", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "lwresd", ver: "1:9.8.4.dfsg.P1-6+nmu1", rls: "DEB7" ) ) != NULL){
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

