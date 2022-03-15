if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.891484" );
	script_version( "2021-06-18T11:00:25+0000" );
	script_cve_id( "CVE-2018-14950", "CVE-2018-14951", "CVE-2018-14952", "CVE-2018-14953", "CVE-2018-14954", "CVE-2018-14955" );
	script_name( "Debian LTS: Security Advisory for squirrelmail (DLA-1484-1)" );
	script_tag( name: "last_modification", value: "2021-06-18 11:00:25 +0000 (Fri, 18 Jun 2021)" );
	script_tag( name: "creation_date", value: "2018-09-03 00:00:00 +0200 (Mon, 03 Sep 2018)" );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:P/A:N" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-08-15 20:15:00 +0000 (Thu, 15 Aug 2019)" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	script_xref( name: "URL", value: "https://lists.debian.org/debian-lts-announce/2018/08/msg00031.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH http://greenbone.net" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB8" );
	script_tag( name: "affected", value: "squirrelmail on Debian Linux" );
	script_tag( name: "solution", value: "For Debian 8 'Jessie', these issues has been fixed in squirrelmail
version 2:1.4.23~svn20120406-2+deb8u3.

We recommend that you upgrade your squirrelmail packages." );
	script_tag( name: "summary", value: "It was discovered that there were a number of Cross Site Scripting
(XSS) vulnerabilities in the squirrelmail webmail client." );
	script_tag( name: "vuldetect", value: "This check tests the installed software version using the apt package manager." );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(!isnull( res = isdpkgvuln( pkg: "squirrelmail", ver: "2:1.4.23~svn20120406-2+deb8u3", rls: "DEB8" ) )){
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

