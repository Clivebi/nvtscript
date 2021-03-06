if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.703955" );
	script_version( "2021-09-16T08:01:42+0000" );
	script_cve_id( "CVE-2017-3636", "CVE-2017-3641", "CVE-2017-3653" );
	script_name( "Debian Security Advisory DSA 3955-1 (mariadb-10.1 - security update)" );
	script_tag( name: "last_modification", value: "2021-09-16 08:01:42 +0000 (Thu, 16 Sep 2021)" );
	script_tag( name: "creation_date", value: "2017-08-26 00:00:00 +0200 (Sat, 26 Aug 2017)" );
	script_tag( name: "cvss_base", value: "4.6" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:L/I:L/A:L" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-10-03 00:03:00 +0000 (Thu, 03 Oct 2019)" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	script_xref( name: "URL", value: "http://www.debian.org/security/2017/dsa-3955.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2017 Greenbone Networks GmbH" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB9" );
	script_tag( name: "affected", value: "mariadb-10.1 on Debian Linux" );
	script_tag( name: "solution", value: "For the stable distribution (stretch), these problems have been fixed
in version 10.1.26-0+deb9u1.

For the unstable distribution (sid), these problems have been fixed in
version 10.1.26-1.

We recommend that you upgrade your mariadb-10.1 packages." );
	script_tag( name: "summary", value: "Several issues have been discovered in the MariaDB database server.
The vulnerabilities are addressed by upgrading MariaDB to the new upstream
version 10.1.26." );
	script_tag( name: "vuldetect", value: "This check tests the installed software version using the apt package manager." );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(( res = isdpkgvuln( pkg: "libmariadbclient-dev", ver: "10.1.26-0+deb9u1", rls: "DEB9" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libmariadbclient-dev-compat", ver: "10.1.26-0+deb9u1", rls: "DEB9" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libmariadbclient18", ver: "10.1.26-0+deb9u1", rls: "DEB9" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libmariadbd-dev", ver: "10.1.26-0+deb9u1", rls: "DEB9" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libmariadbd18", ver: "10.1.26-0+deb9u1", rls: "DEB9" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "mariadb-client", ver: "10.1.26-0+deb9u1", rls: "DEB9" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "mariadb-client-10.1", ver: "10.1.26-0+deb9u1", rls: "DEB9" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "mariadb-client-core-10.1", ver: "10.1.26-0+deb9u1", rls: "DEB9" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "mariadb-common", ver: "10.1.26-0+deb9u1", rls: "DEB9" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "mariadb-plugin-connect", ver: "10.1.26-0+deb9u1", rls: "DEB9" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "mariadb-plugin-cracklib-password-check", ver: "10.1.26-0+deb9u1", rls: "DEB9" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "mariadb-plugin-gssapi-client", ver: "10.1.26-0+deb9u1", rls: "DEB9" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "mariadb-plugin-gssapi-server", ver: "10.1.26-0+deb9u1", rls: "DEB9" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "mariadb-plugin-mroonga", ver: "10.1.26-0+deb9u1", rls: "DEB9" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "mariadb-plugin-oqgraph", ver: "10.1.26-0+deb9u1", rls: "DEB9" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "mariadb-plugin-spider", ver: "10.1.26-0+deb9u1", rls: "DEB9" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "mariadb-plugin-tokudb", ver: "10.1.26-0+deb9u1", rls: "DEB9" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "mariadb-server", ver: "10.1.26-0+deb9u1", rls: "DEB9" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "mariadb-server-10.1", ver: "10.1.26-0+deb9u1", rls: "DEB9" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "mariadb-server-core-10.1", ver: "10.1.26-0+deb9u1", rls: "DEB9" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "mariadb-test", ver: "10.1.26-0+deb9u1", rls: "DEB9" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "mariadb-test-data", ver: "10.1.26-0+deb9u1", rls: "DEB9" ) ) != NULL){
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

