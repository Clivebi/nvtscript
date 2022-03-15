if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.892631" );
	script_version( "2021-08-24T14:01:01+0000" );
	script_cve_id( "CVE-2019-15132", "CVE-2020-15803" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:N/A:N" );
	script_tag( name: "last_modification", value: "2021-08-24 14:01:01 +0000 (Tue, 24 Aug 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-04-27 13:39:00 +0000 (Tue, 27 Apr 2021)" );
	script_tag( name: "creation_date", value: "2021-04-22 03:02:21 +0000 (Thu, 22 Apr 2021)" );
	script_name( "Debian LTS: Security Advisory for zabbix (DLA-2631-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB9" );
	script_xref( name: "URL", value: "https://lists.debian.org/debian-lts-announce/2021/04/msg00018.html" );
	script_xref( name: "URL", value: "https://security-tracker.debian.org/tracker/DLA-2631-1" );
	script_xref( name: "Advisory-ID", value: "DLA-2631-1" );
	script_xref( name: "URL", value: "https://bugs.debian.org/935027" );
	script_xref( name: "URL", value: "https://bugs.debian.org/966146" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'zabbix'
  package(s) announced via the DLA-2631-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "Multiple vulnerabilities were discovered in Zabbix, a network
monitoring solution. An attacker may enumerate valid users and
redirect to external links through the zabbix web frontend.

CVE-2019-15132

Zabbix allows User Enumeration. With login requests, it is
possible to enumerate application usernames based on the
variability of server responses (e.g., the 'Login name or password
is incorrect' and 'No permissions for system access' messages, or
just blocking for a number of seconds). This affects both
api_jsonrpc.php and index.php.

CVE-2020-15803

Zabbix allows stored XSS in the URL Widget. This fix was
mistakenly dropped in previous upload 1:3.0.31+dfsg-0+deb9u1.

This update also includes several other bug fixes and
improvements. For more information please refer to the upstream
changelog file." );
	script_tag( name: "affected", value: "'zabbix' package(s) on Debian Linux." );
	script_tag( name: "solution", value: "For Debian 9 stretch, these problems have been fixed in version
1:3.0.32+dfsg-0+deb9u1.

We recommend that you upgrade your zabbix packages." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(!isnull( res = isdpkgvuln( pkg: "zabbix-agent", ver: "1:3.0.32+dfsg-0+deb9u1", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "zabbix-frontend-php", ver: "1:3.0.32+dfsg-0+deb9u1", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "zabbix-java-gateway", ver: "1:3.0.32+dfsg-0+deb9u1", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "zabbix-proxy-mysql", ver: "1:3.0.32+dfsg-0+deb9u1", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "zabbix-proxy-pgsql", ver: "1:3.0.32+dfsg-0+deb9u1", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "zabbix-proxy-sqlite3", ver: "1:3.0.32+dfsg-0+deb9u1", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "zabbix-server-mysql", ver: "1:3.0.32+dfsg-0+deb9u1", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "zabbix-server-pgsql", ver: "1:3.0.32+dfsg-0+deb9u1", rls: "DEB9" ) )){
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
exit( 0 );

