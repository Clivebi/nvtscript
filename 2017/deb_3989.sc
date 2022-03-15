if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.703989" );
	script_version( "2021-09-08T12:01:36+0000" );
	script_cve_id( "CVE-2017-14491", "CVE-2017-14492", "CVE-2017-14493", "CVE-2017-14494", "CVE-2017-14495", "CVE-2017-14496" );
	script_name( "Debian Security Advisory DSA 3989-1 (dnsmasq - security update)" );
	script_tag( name: "last_modification", value: "2021-09-08 12:01:36 +0000 (Wed, 08 Sep 2021)" );
	script_tag( name: "creation_date", value: "2017-10-02 00:00:00 +0200 (Mon, 02 Oct 2017)" );
	script_tag( name: "cvss_base", value: "7.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:C" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2018-05-11 01:29:00 +0000 (Fri, 11 May 2018)" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	script_xref( name: "URL", value: "http://www.debian.org/security/2017/dsa-3989.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2017 Greenbone Networks GmbH" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB(9|8)" );
	script_tag( name: "affected", value: "dnsmasq on Debian Linux" );
	script_tag( name: "solution", value: "For the oldstable distribution (jessie), these problems have been fixed
in version 2.72-3+deb8u2.

For the stable distribution (stretch), these problems have been fixed in
version 2.76-5+deb9u1.

We recommend that you upgrade your dnsmasq packages." );
	script_tag( name: "summary", value: "Felix Wilhelm, Fermin J. Serna, Gabriel Campana, Kevin Hamacher, Ron
Bowes and Gynvael Coldwind of the Google Security Team discovered
several vulnerabilities in dnsmasq, a small caching DNS proxy and
DHCP/TFTP server, which may result in denial of service, information
leak or the execution of arbitrary code." );
	script_tag( name: "vuldetect", value: "This check tests the installed software version using the apt package manager." );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(( res = isdpkgvuln( pkg: "dnsmasq", ver: "2.76-5+deb9u1", rls: "DEB9" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "dnsmasq-base", ver: "2.76-5+deb9u1", rls: "DEB9" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "dnsmasq-utils", ver: "2.76-5+deb9u1", rls: "DEB9" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "dnsmasq", ver: "2.72-3+deb8u2", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "dnsmasq-base", ver: "2.72-3+deb8u2", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "dnsmasq-utils", ver: "2.72-3+deb8u2", rls: "DEB8" ) ) != NULL){
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

