if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.703711" );
	script_version( "$Revision: 14275 $" );
	script_cve_id( "CVE-2016-3492", "CVE-2016-5584", "CVE-2016-5616", "CVE-2016-5624", "CVE-2016-5626", "CVE-2016-5629", "CVE-2016-6663", "CVE-2016-7440", "CVE-2016-8283" );
	script_name( "Debian Security Advisory DSA 3711-1 (mariadb-10.0 - security update)" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-18 15:39:45 +0100 (Mon, 18 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2016-11-11 00:00:00 +0100 (Fri, 11 Nov 2016)" );
	script_tag( name: "cvss_base", value: "10.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:C/A:C" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	script_xref( name: "URL", value: "http://www.debian.org/security/2016/dsa-3711.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2016 Greenbone Networks GmbH http://greenbone.net" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB(8|9)" );
	script_tag( name: "affected", value: "mariadb-10.0 on Debian Linux" );
	script_tag( name: "solution", value: "For the stable distribution (jessie), these problems have been fixed in
version 10.0.28-0+deb8u1.

For the testing distribution (stretch), these problems have been fixed
in version 10.0.28-1.

For the unstable distribution (sid), these problems have been fixed in
version 10.0.28-1.

We recommend that you upgrade your mariadb-10.0 packages." );
	script_tag( name: "summary", value: "Several issues have been discovered in the MariaDB database server. The
vulnerabilities are addressed by upgrading MariaDB to the new upstream
version 10.0.28." );
	script_tag( name: "vuldetect", value: "This check tests the installed software version using the apt package manager." );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(( res = isdpkgvuln( pkg: "libmariadbd-dev", ver: "10.0.28-0+deb8u1", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "mariadb-client", ver: "10.0.28-0+deb8u1", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "mariadb-client-10.0", ver: "10.0.28-0+deb8u1", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "mariadb-client-core-10.0", ver: "10.0.28-0+deb8u1", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "mariadb-common", ver: "10.0.28-0+deb8u1", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "mariadb-connect-engine-10.0", ver: "10.0.28-0+deb8u1", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "mariadb-oqgraph-engine-10.0", ver: "10.0.28-0+deb8u1", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "mariadb-server", ver: "10.0.28-0+deb8u1", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "mariadb-server-10.0", ver: "10.0.28-0+deb8u1", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "mariadb-server-core-10.0", ver: "10.0.28-0+deb8u1", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "mariadb-test", ver: "10.0.28-0+deb8u1", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "mariadb-test-10.0", ver: "10.0.28-0+deb8u1", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libmariadbclient-dev", ver: "10.0.28-1", rls: "DEB9" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libmariadbclient-dev-compat", ver: "10.0.28-1", rls: "DEB9" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libmariadbclient18", ver: "10.0.28-1", rls: "DEB9" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libmariadbd-dev", ver: "10.0.28-1", rls: "DEB9" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libmariadbd18", ver: "10.0.28-1", rls: "DEB9" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "mariadb-client", ver: "10.0.28-1", rls: "DEB9" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "mariadb-client-10.0", ver: "10.0.28-1", rls: "DEB9" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "mariadb-client-core-10.0", ver: "10.0.28-1", rls: "DEB9" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "mariadb-common", ver: "10.0.28-1", rls: "DEB9" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "mariadb-plugin-connect", ver: "10.0.28-1", rls: "DEB9" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "mariadb-plugin-mroonga", ver: "10.0.28-1", rls: "DEB9" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "mariadb-plugin-oqgraph", ver: "10.0.28-1", rls: "DEB9" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "mariadb-plugin-spider", ver: "10.0.28-1", rls: "DEB9" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "mariadb-plugin-tokudb", ver: "10.0.28-1", rls: "DEB9" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "mariadb-server", ver: "10.0.28-1", rls: "DEB9" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "mariadb-server-10.0", ver: "10.0.28-1", rls: "DEB9" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "mariadb-server-core-10.0", ver: "10.0.28-1", rls: "DEB9" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "mariadb-test", ver: "10.0.28-1", rls: "DEB9" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "mariadb-test-data", ver: "10.0.28-1", rls: "DEB9" ) ) != NULL){
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

