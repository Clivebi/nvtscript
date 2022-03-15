if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.892538" );
	script_version( "2021-08-24T14:01:01+0000" );
	script_cve_id( "CVE-2020-14765", "CVE-2020-14812" );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:S/C:N/I:N/A:C" );
	script_tag( name: "last_modification", value: "2021-08-24 14:01:01 +0000 (Tue, 24 Aug 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-05-26 12:15:00 +0000 (Wed, 26 May 2021)" );
	script_tag( name: "creation_date", value: "2021-02-01 04:00:09 +0000 (Mon, 01 Feb 2021)" );
	script_name( "Debian LTS: Security Advisory for mariadb-10.1 (DLA-2538-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB9" );
	script_xref( name: "URL", value: "https://lists.debian.org/debian-lts-announce/2021/01/msg00027.html" );
	script_xref( name: "URL", value: "https://security-tracker.debian.org/tracker/DLA-2538-1" );
	script_xref( name: "Advisory-ID", value: "DLA-2538-1" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'mariadb-10.1'
  package(s) announced via the DLA-2538-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "Two vulnerabilities were fixed by upgrading the MariaDB database server
packages to the latest version on the 10.1 branch." );
	script_tag( name: "affected", value: "'mariadb-10.1' package(s) on Debian Linux." );
	script_tag( name: "solution", value: "For Debian 9 stretch, these problems have been fixed in version
10.1.48-0+deb9u1.

We recommend that you upgrade your mariadb-10.1 packages." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(!isnull( res = isdpkgvuln( pkg: "libmariadbclient-dev", ver: "10.1.48-0+deb9u1", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libmariadbclient-dev-compat", ver: "10.1.48-0+deb9u1", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libmariadbclient18", ver: "10.1.48-0+deb9u1", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libmariadbd-dev", ver: "10.1.48-0+deb9u1", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libmariadbd18", ver: "10.1.48-0+deb9u1", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "mariadb-client", ver: "10.1.48-0+deb9u1", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "mariadb-client-10.1", ver: "10.1.48-0+deb9u1", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "mariadb-client-core-10.1", ver: "10.1.48-0+deb9u1", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "mariadb-common", ver: "10.1.48-0+deb9u1", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "mariadb-plugin-connect", ver: "10.1.48-0+deb9u1", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "mariadb-plugin-cracklib-password-check", ver: "10.1.48-0+deb9u1", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "mariadb-plugin-gssapi-client", ver: "10.1.48-0+deb9u1", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "mariadb-plugin-gssapi-server", ver: "10.1.48-0+deb9u1", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "mariadb-plugin-mroonga", ver: "10.1.48-0+deb9u1", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "mariadb-plugin-oqgraph", ver: "10.1.48-0+deb9u1", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "mariadb-plugin-spider", ver: "10.1.48-0+deb9u1", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "mariadb-plugin-tokudb", ver: "10.1.48-0+deb9u1", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "mariadb-server", ver: "10.1.48-0+deb9u1", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "mariadb-server-10.1", ver: "10.1.48-0+deb9u1", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "mariadb-server-core-10.1", ver: "10.1.48-0+deb9u1", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "mariadb-test", ver: "10.1.48-0+deb9u1", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "mariadb-test-data", ver: "10.1.48-0+deb9u1", rls: "DEB9" ) )){
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

