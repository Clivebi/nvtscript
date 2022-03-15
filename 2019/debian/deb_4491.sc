if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.704491" );
	script_version( "2021-09-02T14:01:33+0000" );
	script_cve_id( "CVE-2019-12815" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2021-09-02 14:01:33 +0000 (Thu, 02 Sep 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-08-24 17:37:00 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2019-08-06 02:00:09 +0000 (Tue, 06 Aug 2019)" );
	script_name( "Debian Security Advisory DSA 4491-1 (proftpd-dfsg - security update)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2019 Greenbone Networks GmbH" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB(9|10)" );
	script_xref( name: "URL", value: "https://www.debian.org/security/2019/dsa-4491.html" );
	script_xref( name: "URL", value: "https://security-tracker.debian.org/tracker/DSA-4491-1" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'proftpd-dfsg'
  package(s) announced via the DSA-4491-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "Tobias Maedel discovered that the mod_copy module of ProFTPD, a
FTP/SFTP/FTPS server, performed incomplete permission validation for
the CPFR/CPTO commands." );
	script_tag( name: "affected", value: "'proftpd-dfsg' package(s) on Debian Linux." );
	script_tag( name: "solution", value: "For the oldstable distribution (stretch), this problem has been fixed
in version 1.3.5b-4+deb9u1.

For the stable distribution (buster), this problem has been fixed in
version 1.3.6-4+deb10u1.

We recommend that you upgrade your proftpd-dfsg packages." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(!isnull( res = isdpkgvuln( pkg: "proftpd-basic", ver: "1.3.5b-4+deb9u1", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "proftpd-dev", ver: "1.3.5b-4+deb9u1", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "proftpd-doc", ver: "1.3.5b-4+deb9u1", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "proftpd-mod-geoip", ver: "1.3.5b-4+deb9u1", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "proftpd-mod-ldap", ver: "1.3.5b-4+deb9u1", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "proftpd-mod-mysql", ver: "1.3.5b-4+deb9u1", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "proftpd-mod-odbc", ver: "1.3.5b-4+deb9u1", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "proftpd-mod-pgsql", ver: "1.3.5b-4+deb9u1", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "proftpd-mod-sqlite", ver: "1.3.5b-4+deb9u1", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "proftpd-basic", ver: "1.3.6-4+deb10u1", rls: "DEB10" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "proftpd-dev", ver: "1.3.6-4+deb10u1", rls: "DEB10" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "proftpd-doc", ver: "1.3.6-4+deb10u1", rls: "DEB10" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "proftpd-mod-geoip", ver: "1.3.6-4+deb10u1", rls: "DEB10" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "proftpd-mod-ldap", ver: "1.3.6-4+deb10u1", rls: "DEB10" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "proftpd-mod-mysql", ver: "1.3.6-4+deb10u1", rls: "DEB10" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "proftpd-mod-odbc", ver: "1.3.6-4+deb10u1", rls: "DEB10" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "proftpd-mod-pgsql", ver: "1.3.6-4+deb10u1", rls: "DEB10" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "proftpd-mod-snmp", ver: "1.3.6-4+deb10u1", rls: "DEB10" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "proftpd-mod-sqlite", ver: "1.3.6-4+deb10u1", rls: "DEB10" ) )){
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

