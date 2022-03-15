if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.891396" );
	script_version( "2021-06-18T02:00:26+0000" );
	script_cve_id( "CVE-2018-11218", "CVE-2018-11219", "CVE-2018-12326" );
	script_name( "Debian LTS: Security Advisory for redis (DLA-1396-1)" );
	script_tag( name: "last_modification", value: "2021-06-18 02:00:26 +0000 (Fri, 18 Jun 2021)" );
	script_tag( name: "creation_date", value: "2018-07-10 00:00:00 +0200 (Tue, 10 Jul 2018)" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-08-24 17:37:00 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	script_xref( name: "URL", value: "https://lists.debian.org/debian-lts-announce/2018/06/msg00003.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH http://greenbone.net" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB8" );
	script_tag( name: "affected", value: "redis on Debian Linux" );
	script_tag( name: "solution", value: "For Debian 8 'Jessie', these issues have been fixed in redis version
2:2.8.17-1+deb8u6.

We recommend that you upgrade your redis packages." );
	script_tag( name: "summary", value: "It was discovered that there were a number of vulnerabilities in redis,
a persistent key-value database:

  * CVE-2018-11218, CVE-2018-11219: Multiple heap
corruption and integer overflow vulnerabilities. (#901495)

  * CVE-2018-12326: Buffer overflow in the 'redis-cli' tool which could
have allowed an attacker to achieve code execution and/or escalate to
higher privileges via a crafted command line. (#902410)" );
	script_tag( name: "vuldetect", value: "This check tests the installed software version using the apt package manager." );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(!isnull( res = isdpkgvuln( pkg: "redis-server", ver: "2:2.8.17-1+deb8u6", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "redis-tools", ver: "2:2.8.17-1+deb8u6", rls: "DEB8" ) )){
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

