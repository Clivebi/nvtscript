if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.703319" );
	script_version( "$Revision: 14275 $" );
	script_cve_id( "CVE-2015-5477" );
	script_name( "Debian Security Advisory DSA 3319-1 (bind9 - security update)" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-18 15:39:45 +0100 (Mon, 18 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2015-07-28 00:00:00 +0200 (Tue, 28 Jul 2015)" );
	script_tag( name: "cvss_base", value: "7.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:C" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	script_xref( name: "URL", value: "http://www.debian.org/security/2015/dsa-3319.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2015 Greenbone Networks GmbH http://greenbone.net" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB7" );
	script_tag( name: "affected", value: "bind9 on Debian Linux" );
	script_tag( name: "solution", value: "For the oldstable distribution (wheezy), this problem has been fixed
in version 1:9.8.4.dfsg.P1-6+nmu2+deb7u6.

For the stable distribution (jessie), this problem has been fixed in
version 1:9.9.5.dfsg-9+deb8u2.

We recommend that you upgrade your bind9 packages." );
	script_tag( name: "summary", value: "Jonathan Foote discovered that the BIND DNS server does not properly
handle TKEY queries. A remote attacker can take advantage of this flaw
to mount a denial of service via a specially crafted query triggering an
assertion failure and causing BIND to exit." );
	script_tag( name: "vuldetect", value: "This check tests the installed software version using the apt package manager." );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(( res = isdpkgvuln( pkg: "bind9", ver: "1:9.8.4.dfsg.P1-6+nmu2+deb7u6", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "bind9-doc", ver: "1:9.8.4.dfsg.P1-6+nmu2+deb7u6", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "bind9-host", ver: "1:9.8.4.dfsg.P1-6+nmu2+deb7u6", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "bind9utils", ver: "1:9.8.4.dfsg.P1-6+nmu2+deb7u6", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "dnsutils", ver: "1:9.8.4.dfsg.P1-6+nmu2+deb7u6", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "host", ver: "1:9.8.4.dfsg.P1-6+nmu2+deb7u6", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libbind-dev", ver: "1:9.8.4.dfsg.P1-6+nmu2+deb7u6", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libbind9-80", ver: "1:9.8.4.dfsg.P1-6+nmu2+deb7u6", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libdns88", ver: "1:9.8.4.dfsg.P1-6+nmu2+deb7u6", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libisc84", ver: "1:9.8.4.dfsg.P1-6+nmu2+deb7u6", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libisccc80", ver: "1:9.8.4.dfsg.P1-6+nmu2+deb7u6", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libisccfg82", ver: "1:9.8.4.dfsg.P1-6+nmu2+deb7u6", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "liblwres80", ver: "1:9.8.4.dfsg.P1-6+nmu2+deb7u6", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "lwresd", ver: "1:9.8.4.dfsg.P1-6+nmu2+deb7u6", rls: "DEB7" ) ) != NULL){
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

