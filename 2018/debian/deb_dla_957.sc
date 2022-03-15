if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.890957" );
	script_version( "2021-06-18T02:00:26+0000" );
	script_cve_id( "CVE-2017-3136", "CVE-2017-3137", "CVE-2017-3138" );
	script_name( "Debian LTS: Security Advisory for bind9 (DLA-957-1)" );
	script_tag( name: "last_modification", value: "2021-06-18 02:00:26 +0000 (Fri, 18 Jun 2021)" );
	script_tag( name: "creation_date", value: "2018-01-26 00:00:00 +0100 (Fri, 26 Jan 2018)" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-10-09 23:27:00 +0000 (Wed, 09 Oct 2019)" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	script_xref( name: "URL", value: "https://lists.debian.org/debian-lts-announce/2017/05/msg00028.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH http://greenbone.net" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB7" );
	script_tag( name: "affected", value: "bind9 on Debian Linux" );
	script_tag( name: "solution", value: "For Debian 7 'Wheezy', these problems have been fixed in version
1:9.8.4.dfsg.P1-6+nmu2+deb7u16.

We recommend that you upgrade your bind9 packages." );
	script_tag( name: "summary", value: "CVE-2017-3136

Oleg Gorokhov of Yandex discovered that BIND does not properly
handle certain queries when using DNS64 with the 'break-dnssec yes<semicolon>'
option, allowing a remote attacker to cause a denial-of-service.

CVE-2017-3137

It was discovered that BIND makes incorrect assumptions about the
ordering of records in the answer section of a response containing
CNAME or DNAME resource records, leading to situations where BIND
exits with an assertion failure. An attacker can take advantage of
this condition to cause a denial-of-service.

CVE-2017-3138

Mike Lalumiere of Dyn, Inc. discovered that BIND can exit with a
REQUIRE assertion failure if it receives a null command string on
its control channel. Note that the fix applied in Debian is only
applied as a hardening measure." );
	script_tag( name: "vuldetect", value: "This check tests the installed software version using the apt package manager." );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(!isnull( res = isdpkgvuln( pkg: "bind9", ver: "1:9.8.4.dfsg.P1-6+nmu2+deb7u16", rls: "DEB7" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "bind9-doc", ver: "1:9.8.4.dfsg.P1-6+nmu2+deb7u16", rls: "DEB7" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "bind9-host", ver: "1:9.8.4.dfsg.P1-6+nmu2+deb7u16", rls: "DEB7" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "bind9utils", ver: "1:9.8.4.dfsg.P1-6+nmu2+deb7u16", rls: "DEB7" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "dnsutils", ver: "1:9.8.4.dfsg.P1-6+nmu2+deb7u16", rls: "DEB7" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "host", ver: "1:9.8.4.dfsg.P1-6+nmu2+deb7u16", rls: "DEB7" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libbind-dev", ver: "1:9.8.4.dfsg.P1-6+nmu2+deb7u16", rls: "DEB7" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libbind9-80", ver: "1:9.8.4.dfsg.P1-6+nmu2+deb7u16", rls: "DEB7" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libdns88", ver: "1:9.8.4.dfsg.P1-6+nmu2+deb7u16", rls: "DEB7" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libisc84", ver: "1:9.8.4.dfsg.P1-6+nmu2+deb7u16", rls: "DEB7" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libisccc80", ver: "1:9.8.4.dfsg.P1-6+nmu2+deb7u16", rls: "DEB7" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libisccfg82", ver: "1:9.8.4.dfsg.P1-6+nmu2+deb7u16", rls: "DEB7" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "liblwres80", ver: "1:9.8.4.dfsg.P1-6+nmu2+deb7u16", rls: "DEB7" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "lwresd", ver: "1:9.8.4.dfsg.P1-6+nmu2+deb7u16", rls: "DEB7" ) )){
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

