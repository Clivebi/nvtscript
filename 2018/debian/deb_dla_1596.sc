if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.891596" );
	script_version( "2021-06-16T11:00:23+0000" );
	script_cve_id( "CVE-2018-19132" );
	script_name( "Debian LTS: Security Advisory for squid3 (DLA-1596-1)" );
	script_tag( name: "last_modification", value: "2021-06-16 11:00:23 +0000 (Wed, 16 Jun 2021)" );
	script_tag( name: "creation_date", value: "2018-11-26 00:00:00 +0100 (Mon, 26 Nov 2018)" );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:N/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:N/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-07-11 00:15:00 +0000 (Sat, 11 Jul 2020)" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	script_xref( name: "URL", value: "https://lists.debian.org/debian-lts-announce/2018/11/msg00032.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH http://greenbone.net" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB8" );
	script_tag( name: "affected", value: "squid3 on Debian Linux" );
	script_tag( name: "solution", value: "For Debian 8 'Jessie', this problem has been fixed in version
3.4.8-6+deb8u6.

We recommend that you upgrade your squid3 packages." );
	script_tag( name: "summary", value: "It was discovered that there can be a denial of service (DoS)
vulnerability in squid3 due to a memory leak in SNMP query rejection
code when SNMP is enabled. In environments where per-process memory
restrictions are not enforced strictly, a remote attacker to consume
all memory available to the Squid process, causing it to crash." );
	script_tag( name: "vuldetect", value: "This check tests the installed software version using the apt package manager." );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(!isnull( res = isdpkgvuln( pkg: "squid-cgi", ver: "3.4.8-6+deb8u6", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "squid-purge", ver: "3.4.8-6+deb8u6", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "squid3", ver: "3.4.8-6+deb8u6", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "squid3-common", ver: "3.4.8-6+deb8u6", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "squid3-dbg", ver: "3.4.8-6+deb8u6", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "squidclient", ver: "3.4.8-6+deb8u6", rls: "DEB8" ) )){
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

