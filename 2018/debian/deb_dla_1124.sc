if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.891124" );
	script_version( "2021-06-21T02:00:27+0000" );
	script_cve_id( "CVE-2017-14491", "CVE-2017-14492", "CVE-2017-14494" );
	script_name( "Debian LTS: Security Advisory for dnsmasq (DLA-1124-1)" );
	script_tag( name: "last_modification", value: "2021-06-21 02:00:27 +0000 (Mon, 21 Jun 2021)" );
	script_tag( name: "creation_date", value: "2018-02-07 00:00:00 +0100 (Wed, 07 Feb 2018)" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2018-05-11 01:29:00 +0000 (Fri, 11 May 2018)" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	script_xref( name: "URL", value: "https://lists.debian.org/debian-lts-announce/2017/10/msg00004.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH http://greenbone.net" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB7" );
	script_tag( name: "affected", value: "dnsmasq on Debian Linux" );
	script_tag( name: "solution", value: "For Debian 7 'Wheezy', these problems have been fixed in version
2.62-3+deb7u4.

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
if(!isnull( res = isdpkgvuln( pkg: "dnsmasq", ver: "2.62-3+deb7u4", rls: "DEB7" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "dnsmasq-base", ver: "2.62-3+deb7u4", rls: "DEB7" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "dnsmasq-utils", ver: "2.62-3+deb7u4", rls: "DEB7" ) )){
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

