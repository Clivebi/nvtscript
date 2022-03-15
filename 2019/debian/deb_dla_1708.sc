if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.891708" );
	script_version( "2021-09-03T11:01:27+0000" );
	script_cve_id( "CVE-2016-10742", "CVE-2017-2826" );
	script_name( "Debian LTS: Security Advisory for zabbix (DLA-1708-1)" );
	script_tag( name: "last_modification", value: "2021-09-03 11:01:27 +0000 (Fri, 03 Sep 2021)" );
	script_tag( name: "creation_date", value: "2019-03-12 00:00:00 +0100 (Tue, 12 Mar 2019)" );
	script_tag( name: "cvss_base", value: "5.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:N" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-11-21 20:15:00 +0000 (Sat, 21 Nov 2020)" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	script_xref( name: "URL", value: "https://lists.debian.org/debian-lts-announce/2019/03/msg00010.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2019 Greenbone Networks GmbH" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB8" );
	script_tag( name: "affected", value: "zabbix on Debian Linux" );
	script_tag( name: "solution", value: "For Debian 8 'Jessie', these problems have been fixed in version
1:2.2.23+dfsg-0+deb8u1.

We recommend that you upgrade your zabbix packages." );
	script_tag( name: "summary", value: "Several security vulnerabilities were discovered in Zabbix, a
server/client network monitoring solution.

CVE-2016-10742

Zabbix allowed remote attackers to redirect to external links by
misusing the request parameter.

CVE-2017-2826

An information disclosure vulnerability exists in the iConfig proxy
request of Zabbix server. A specially crafted iConfig proxy request
can cause the Zabbix server to send the configuration information of
any Zabbix proxy, resulting in information disclosure. An attacker
can make requests from an active Zabbix proxy to trigger this
vulnerability.

This update also includes several other bug fixes and improvements. For
more information please refer to the upstream changelog file." );
	script_tag( name: "vuldetect", value: "This check tests the installed software version using the apt package manager." );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(!isnull( res = isdpkgvuln( pkg: "zabbix-agent", ver: "1:2.2.23+dfsg-0+deb8u1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "zabbix-frontend-php", ver: "1:2.2.23+dfsg-0+deb8u1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "zabbix-java-gateway", ver: "1:2.2.23+dfsg-0+deb8u1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "zabbix-proxy-mysql", ver: "1:2.2.23+dfsg-0+deb8u1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "zabbix-proxy-pgsql", ver: "1:2.2.23+dfsg-0+deb8u1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "zabbix-proxy-sqlite3", ver: "1:2.2.23+dfsg-0+deb8u1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "zabbix-server-mysql", ver: "1:2.2.23+dfsg-0+deb8u1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "zabbix-server-pgsql", ver: "1:2.2.23+dfsg-0+deb8u1", rls: "DEB8" ) )){
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

