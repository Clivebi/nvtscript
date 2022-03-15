if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.704559" );
	script_version( "2021-09-02T14:01:33+0000" );
	script_cve_id( "CVE-2019-18217" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:P" );
	script_tag( name: "last_modification", value: "2021-09-02 14:01:33 +0000 (Thu, 02 Sep 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-10-27 21:15:00 +0000 (Sun, 27 Oct 2019)" );
	script_tag( name: "creation_date", value: "2019-11-07 03:00:12 +0000 (Thu, 07 Nov 2019)" );
	script_name( "Debian Security Advisory DSA 4559-1 (proftpd-dfsg - security update)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2019 Greenbone Networks GmbH" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB(10|9)" );
	script_xref( name: "URL", value: "https://www.debian.org/security/2019/dsa-4559.html" );
	script_xref( name: "URL", value: "https://security-tracker.debian.org/tracker/DSA-4559-1" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'proftpd-dfsg'
  package(s) announced via the DSA-4559-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "Stephan Zeisberg discovered that missing input validation in ProFTPD, a
FTP/SFTP/FTPS server, could result in denial of service via an infinite
loop." );
	script_tag( name: "affected", value: "'proftpd-dfsg' package(s) on Debian Linux." );
	script_tag( name: "solution", value: "For the oldstable distribution (stretch), this problem has been fixed
in version 1.3.5b-4+deb9u2.

For the stable distribution (buster), this problem has been fixed in
version 1.3.6-4+deb10u2.

We recommend that you upgrade your proftpd-dfsg packages." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(!isnull( res = isdpkgvuln( pkg: "proftpd-basic", ver: "1.3.6-4+deb10u2", rls: "DEB10" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "proftpd-dev", ver: "1.3.6-4+deb10u2", rls: "DEB10" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "proftpd-doc", ver: "1.3.6-4+deb10u2", rls: "DEB10" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "proftpd-mod-geoip", ver: "1.3.6-4+deb10u2", rls: "DEB10" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "proftpd-mod-ldap", ver: "1.3.6-4+deb10u2", rls: "DEB10" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "proftpd-mod-mysql", ver: "1.3.6-4+deb10u2", rls: "DEB10" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "proftpd-mod-odbc", ver: "1.3.6-4+deb10u2", rls: "DEB10" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "proftpd-mod-pgsql", ver: "1.3.6-4+deb10u2", rls: "DEB10" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "proftpd-mod-snmp", ver: "1.3.6-4+deb10u2", rls: "DEB10" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "proftpd-mod-sqlite", ver: "1.3.6-4+deb10u2", rls: "DEB10" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "proftpd-basic", ver: "1.3.5b-4+deb9u2", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "proftpd-dev", ver: "1.3.5b-4+deb9u2", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "proftpd-doc", ver: "1.3.5b-4+deb9u2", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "proftpd-mod-geoip", ver: "1.3.5b-4+deb9u2", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "proftpd-mod-ldap", ver: "1.3.5b-4+deb9u2", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "proftpd-mod-mysql", ver: "1.3.5b-4+deb9u2", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "proftpd-mod-odbc", ver: "1.3.5b-4+deb9u2", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "proftpd-mod-pgsql", ver: "1.3.5b-4+deb9u2", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "proftpd-mod-sqlite", ver: "1.3.5b-4+deb9u2", rls: "DEB9" ) )){
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

