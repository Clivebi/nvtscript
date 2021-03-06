if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.703937" );
	script_version( "2021-09-17T09:09:50+0000" );
	script_cve_id( "CVE-2017-2824", "CVE-2017-2825" );
	script_name( "Debian Security Advisory DSA 3937-1 (zabbix - security update)" );
	script_tag( name: "last_modification", value: "2021-09-17 09:09:50 +0000 (Fri, 17 Sep 2021)" );
	script_tag( name: "creation_date", value: "2017-08-12 00:00:00 +0200 (Sat, 12 Aug 2017)" );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-10-03 00:03:00 +0000 (Thu, 03 Oct 2019)" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	script_xref( name: "URL", value: "http://www.debian.org/security/2017/dsa-3937.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2017 Greenbone Networks GmbH" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB8" );
	script_tag( name: "affected", value: "zabbix on Debian Linux" );
	script_tag( name: "solution", value: "For the oldstable distribution (jessie), these problems have been fixed
in version 1:2.2.7+dfsg-2+deb8u3.

For the stable distribution (stretch), these problems have been fixed
prior to the initial release.

We recommend that you upgrade your zabbix packages." );
	script_tag( name: "summary", value: "Lilith Wyatt discovered two vulnerabilities in the Zabbix network
monitoring system which may result in execution of arbitrary code or
database writes by malicious proxies." );
	script_tag( name: "vuldetect", value: "This check tests the installed software version using the apt package manager." );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(( res = isdpkgvuln( pkg: "zabbix-agent", ver: "1:2.2.7+dfsg-2+deb8u3", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "zabbix-frontend-php", ver: "1:2.2.7+dfsg-2+deb8u3", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "zabbix-java-gateway", ver: "1:2.2.7+dfsg-2+deb8u3", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "zabbix-proxy-mysql", ver: "1:2.2.7+dfsg-2+deb8u3", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "zabbix-proxy-pgsql", ver: "1:2.2.7+dfsg-2+deb8u3", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "zabbix-proxy-sqlite3", ver: "1:2.2.7+dfsg-2+deb8u3", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "zabbix-server-mysql", ver: "1:2.2.7+dfsg-2+deb8u3", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "zabbix-server-pgsql", ver: "1:2.2.7+dfsg-2+deb8u3", rls: "DEB8" ) ) != NULL){
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

