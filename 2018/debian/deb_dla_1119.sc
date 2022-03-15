if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.891119" );
	script_version( "2021-06-17T11:00:26+0000" );
	script_cve_id( "CVE-2014-1695", "CVE-2014-2553", "CVE-2014-2554", "CVE-2017-14635" );
	script_name( "Debian LTS: Security Advisory for otrs2 (DLA-1119-1)" );
	script_tag( name: "last_modification", value: "2021-06-17 11:00:26 +0000 (Thu, 17 Jun 2021)" );
	script_tag( name: "creation_date", value: "2018-02-07 00:00:00 +0100 (Wed, 07 Feb 2018)" );
	script_tag( name: "cvss_base", value: "6.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:S/C:P/I:P/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-10-03 00:03:00 +0000 (Thu, 03 Oct 2019)" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	script_xref( name: "URL", value: "https://lists.debian.org/debian-lts-announce/2017/09/msg00036.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH http://greenbone.net" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB7" );
	script_tag( name: "affected", value: "otrs2 on Debian Linux" );
	script_tag( name: "solution", value: "For Debian 7 'Wheezy', these problems have been fixed in version
3.3.18-1~deb7u1.

We recommend that you upgrade your otrs2 packages." );
	script_tag( name: "summary", value: "n attacker who is logged into OTRS, a Ticket Request System, as an
agent with write permissions for statistics can inject arbitrary code
into the system. This can lead to serious problems like privilege
escalation, data loss, and denial of service. This issue is also known
as CVE-2017-14635 and is resolved by upgrading to the latest upstream
release of OTRS3.

****IMPORTANT UPGRADE NOTES****
===============================

This update requires manual intervention. We strongly recommend to
backup all files and databases before upgrading. If you use the MySQL
backend you should read Debian bug report #707075 and the included
README.Debian file which will provide further information.

If you discover that the maintenance mode is still activated after the
update, we recommend to remove /etc/otrs/maintenance.html and
/var/lib/otrs/httpd/htdocs/maintenance.html which will resolve the issue
.

In addition the following security vulnerabilities were also addressed:

CVE-2014-1695
Cross-site scripting (XSS) vulnerability in OTRS allows remote
attackers to inject arbitrary web script or HTML via a crafted HTML
email

CVE-2014-2553
Cross-site scripting (XSS) vulnerability in OTRS allows remote
authenticated users to inject arbitrary web script or HTML via
vectors related to dynamic fields

CVE-2014-2554
OTRS allows remote attackers to conduct clickjacking attacks via an
IFRAME element" );
	script_tag( name: "vuldetect", value: "This check tests the installed software version using the apt package manager." );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(!isnull( res = isdpkgvuln( pkg: "otrs", ver: "3.3.18-1~deb7u1", rls: "DEB7" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "otrs2", ver: "3.3.18-1~deb7u1", rls: "DEB7" ) )){
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

