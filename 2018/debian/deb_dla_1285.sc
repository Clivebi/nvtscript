if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.891285" );
	script_version( "2021-06-16T02:47:07+0000" );
	script_cve_id( "CVE-2017-3139", "CVE-2018-5735" );
	script_name( "Debian LTS: Security Advisory for bind9 (DLA-1285-1)" );
	script_tag( name: "last_modification", value: "2021-06-16 02:47:07 +0000 (Wed, 16 Jun 2021)" );
	script_tag( name: "creation_date", value: "2018-02-21 00:00:00 +0100 (Wed, 21 Feb 2018)" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-05-14 20:35:00 +0000 (Fri, 14 May 2021)" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	script_xref( name: "URL", value: "https://lists.debian.org/debian-lts-announce/2018/02/msg00020.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH http://greenbone.net" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB7" );
	script_tag( name: "affected", value: "bind9 on Debian Linux" );
	script_tag( name: "solution", value: "For Debian 7 'Wheezy', these problems have been fixed in version
9.8.4.dfsg.P1-6+nmu2+deb7u20.

We recommend that you upgrade your bind9 packages." );
	script_tag( name: "summary", value: "BIND, a DNS server implementation, was found to be vulnerable to a denial
of service flaw was found in the handling of DNSSEC validation. A remote
attacker could use this flaw to make named exit unexpectedly with an
assertion failure via a specially crafted DNS response. This issue is
closely related to CVE-2017-3139." );
	script_tag( name: "vuldetect", value: "This check tests the installed software version using the apt package manager." );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(!isnull( res = isdpkgvuln( pkg: "bind9", ver: "9.8.4.dfsg.P1-6+nmu2+deb7u20", rls: "DEB7" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "bind9-doc", ver: "9.8.4.dfsg.P1-6+nmu2+deb7u20", rls: "DEB7" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "bind9-host", ver: "9.8.4.dfsg.P1-6+nmu2+deb7u20", rls: "DEB7" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "bind9utils", ver: "9.8.4.dfsg.P1-6+nmu2+deb7u20", rls: "DEB7" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "dnsutils", ver: "9.8.4.dfsg.P1-6+nmu2+deb7u20", rls: "DEB7" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "host", ver: "9.8.4.dfsg.P1-6+nmu2+deb7u20", rls: "DEB7" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libbind-dev", ver: "9.8.4.dfsg.P1-6+nmu2+deb7u20", rls: "DEB7" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libbind9-80", ver: "9.8.4.dfsg.P1-6+nmu2+deb7u20", rls: "DEB7" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libdns88", ver: "9.8.4.dfsg.P1-6+nmu2+deb7u20", rls: "DEB7" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libisc84", ver: "9.8.4.dfsg.P1-6+nmu2+deb7u20", rls: "DEB7" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libisccc80", ver: "9.8.4.dfsg.P1-6+nmu2+deb7u20", rls: "DEB7" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libisccfg82", ver: "9.8.4.dfsg.P1-6+nmu2+deb7u20", rls: "DEB7" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "liblwres80", ver: "9.8.4.dfsg.P1-6+nmu2+deb7u20", rls: "DEB7" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "lwresd", ver: "9.8.4.dfsg.P1-6+nmu2+deb7u20", rls: "DEB7" ) )){
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

