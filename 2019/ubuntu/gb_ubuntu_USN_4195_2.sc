if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.844245" );
	script_version( "2021-08-31T11:01:29+0000" );
	script_cve_id( "CVE-2019-2974", "CVE-2019-2938" );
	script_tag( name: "cvss_base", value: "4.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:S/C:N/I:N/A:P" );
	script_tag( name: "last_modification", value: "2021-08-31 11:01:29 +0000 (Tue, 31 Aug 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-05-26 12:15:00 +0000 (Wed, 26 May 2021)" );
	script_tag( name: "creation_date", value: "2019-11-21 03:00:40 +0000 (Thu, 21 Nov 2019)" );
	script_name( "Ubuntu Update for mariadb-10.3 USN-4195-2" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2019 Greenbone Networks GmbH" );
	script_family( "Ubuntu Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/ubuntu_linux", "ssh/login/packages",  "ssh/login/release=(UBUNTU18\\.04 LTS|UBUNTU19\\.10|UBUNTU19\\.04)" );
	script_xref( name: "USN", value: "4195-2" );
	script_xref( name: "URL", value: "https://lists.ubuntu.com/archives/ubuntu-security-announce/2019-November/005215.html" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'mariadb-10.3'
  package(s) announced via the USN-4195-2 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "USN-4195-1 fixed multiple vulnerabilities in MySQL. This update provides the
corresponding fixes for CVE-2019-2974 in MariaDB 10.1 and CVE-2019-2938,
CVE-2019-2974 for MariaDB 10.3.

Ubuntu 18.04 LTS has been updated to MariaDB 10.1.43.
Ubuntu 19.04 and 19.10 has been updated to MariaDB 10.3.20.

Original advisory details:

Multiple security issues were discovered in MySQL and this update includes
new upstream MySQL versions to fix these issues.

MySQL has been updated to 8.0.18 in Ubuntu 19.10. Ubuntu 16.04 LTS,
Ubuntu 18.04 LTS, and Ubuntu 19.04 have been updated to MySQL 5.7.28." );
	script_tag( name: "affected", value: "'mariadb-10.3' package(s) on Ubuntu 19.10, Ubuntu 19.04, Ubuntu 18.04 LTS." );
	script_tag( name: "solution", value: "Please install the updated package(s)." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
release = dpkg_get_ssh_release();
if(!release){
	exit( 0 );
}
res = "";
report = "";
if(release == "UBUNTU18.04 LTS"){
	if(!isnull( res = isdpkgvuln( pkg: "libmariadbclient-dev", ver: "1:10.1.43-0ubuntu0.18.04.1", rls: "UBUNTU18.04 LTS" ) )){
		report += res;
	}
	if(!isnull( res = isdpkgvuln( pkg: "libmariadbclient-dev-compat", ver: "1:10.1.43-0ubuntu0.18.04.1", rls: "UBUNTU18.04 LTS" ) )){
		report += res;
	}
	if(!isnull( res = isdpkgvuln( pkg: "libmariadbclient18", ver: "1:10.1.43-0ubuntu0.18.04.1", rls: "UBUNTU18.04 LTS" ) )){
		report += res;
	}
	if(!isnull( res = isdpkgvuln( pkg: "libmariadbd-dev", ver: "1:10.1.43-0ubuntu0.18.04.1", rls: "UBUNTU18.04 LTS" ) )){
		report += res;
	}
	if(!isnull( res = isdpkgvuln( pkg: "libmariadbd18", ver: "1:10.1.43-0ubuntu0.18.04.1", rls: "UBUNTU18.04 LTS" ) )){
		report += res;
	}
	if(!isnull( res = isdpkgvuln( pkg: "mariadb-client", ver: "1:10.1.43-0ubuntu0.18.04.1", rls: "UBUNTU18.04 LTS" ) )){
		report += res;
	}
	if(!isnull( res = isdpkgvuln( pkg: "mariadb-client-10.1", ver: "1:10.1.43-0ubuntu0.18.04.1", rls: "UBUNTU18.04 LTS" ) )){
		report += res;
	}
	if(!isnull( res = isdpkgvuln( pkg: "mariadb-client-core-10.1", ver: "1:10.1.43-0ubuntu0.18.04.1", rls: "UBUNTU18.04 LTS" ) )){
		report += res;
	}
	if(!isnull( res = isdpkgvuln( pkg: "mariadb-common", ver: "1:10.1.43-0ubuntu0.18.04.1", rls: "UBUNTU18.04 LTS" ) )){
		report += res;
	}
	if(!isnull( res = isdpkgvuln( pkg: "mariadb-plugin-connect", ver: "1:10.1.43-0ubuntu0.18.04.1", rls: "UBUNTU18.04 LTS" ) )){
		report += res;
	}
	if(!isnull( res = isdpkgvuln( pkg: "mariadb-plugin-cracklib-password-check", ver: "1:10.1.43-0ubuntu0.18.04.1", rls: "UBUNTU18.04 LTS" ) )){
		report += res;
	}
	if(!isnull( res = isdpkgvuln( pkg: "mariadb-plugin-gssapi-client", ver: "1:10.1.43-0ubuntu0.18.04.1", rls: "UBUNTU18.04 LTS" ) )){
		report += res;
	}
	if(!isnull( res = isdpkgvuln( pkg: "mariadb-plugin-gssapi-server", ver: "1:10.1.43-0ubuntu0.18.04.1", rls: "UBUNTU18.04 LTS" ) )){
		report += res;
	}
	if(!isnull( res = isdpkgvuln( pkg: "mariadb-plugin-mroonga", ver: "1:10.1.43-0ubuntu0.18.04.1", rls: "UBUNTU18.04 LTS" ) )){
		report += res;
	}
	if(!isnull( res = isdpkgvuln( pkg: "mariadb-plugin-oqgraph", ver: "1:10.1.43-0ubuntu0.18.04.1", rls: "UBUNTU18.04 LTS" ) )){
		report += res;
	}
	if(!isnull( res = isdpkgvuln( pkg: "mariadb-plugin-spider", ver: "1:10.1.43-0ubuntu0.18.04.1", rls: "UBUNTU18.04 LTS" ) )){
		report += res;
	}
	if(!isnull( res = isdpkgvuln( pkg: "mariadb-plugin-tokudb", ver: "1:10.1.43-0ubuntu0.18.04.1", rls: "UBUNTU18.04 LTS" ) )){
		report += res;
	}
	if(!isnull( res = isdpkgvuln( pkg: "mariadb-server", ver: "1:10.1.43-0ubuntu0.18.04.1", rls: "UBUNTU18.04 LTS" ) )){
		report += res;
	}
	if(!isnull( res = isdpkgvuln( pkg: "mariadb-server-10.1", ver: "1:10.1.43-0ubuntu0.18.04.1", rls: "UBUNTU18.04 LTS" ) )){
		report += res;
	}
	if(!isnull( res = isdpkgvuln( pkg: "mariadb-server-core-10.1", ver: "1:10.1.43-0ubuntu0.18.04.1", rls: "UBUNTU18.04 LTS" ) )){
		report += res;
	}
	if(!isnull( res = isdpkgvuln( pkg: "mariadb-test", ver: "1:10.1.43-0ubuntu0.18.04.1", rls: "UBUNTU18.04 LTS" ) )){
		report += res;
	}
	if(!isnull( res = isdpkgvuln( pkg: "mariadb-test-data", ver: "1:10.1.43-0ubuntu0.18.04.1", rls: "UBUNTU18.04 LTS" ) )){
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
}
if(release == "UBUNTU19.10"){
	if(!isnull( res = isdpkgvuln( pkg: "libmariadb-dev", ver: "1:10.3.20-0ubuntu0.19.10.1", rls: "UBUNTU19.10" ) )){
		report += res;
	}
	if(!isnull( res = isdpkgvuln( pkg: "libmariadb-dev-compat", ver: "1:10.3.20-0ubuntu0.19.10.1", rls: "UBUNTU19.10" ) )){
		report += res;
	}
	if(!isnull( res = isdpkgvuln( pkg: "libmariadb3", ver: "1:10.3.20-0ubuntu0.19.10.1", rls: "UBUNTU19.10" ) )){
		report += res;
	}
	if(!isnull( res = isdpkgvuln( pkg: "libmariadbclient-dev", ver: "1:10.3.20-0ubuntu0.19.10.1", rls: "UBUNTU19.10" ) )){
		report += res;
	}
	if(!isnull( res = isdpkgvuln( pkg: "libmariadbd-dev", ver: "1:10.3.20-0ubuntu0.19.10.1", rls: "UBUNTU19.10" ) )){
		report += res;
	}
	if(!isnull( res = isdpkgvuln( pkg: "libmariadbd19", ver: "1:10.3.20-0ubuntu0.19.10.1", rls: "UBUNTU19.10" ) )){
		report += res;
	}
	if(!isnull( res = isdpkgvuln( pkg: "mariadb-backup", ver: "1:10.3.20-0ubuntu0.19.10.1", rls: "UBUNTU19.10" ) )){
		report += res;
	}
	if(!isnull( res = isdpkgvuln( pkg: "mariadb-client", ver: "1:10.3.20-0ubuntu0.19.10.1", rls: "UBUNTU19.10" ) )){
		report += res;
	}
	if(!isnull( res = isdpkgvuln( pkg: "mariadb-client-10.3", ver: "1:10.3.20-0ubuntu0.19.10.1", rls: "UBUNTU19.10" ) )){
		report += res;
	}
	if(!isnull( res = isdpkgvuln( pkg: "mariadb-client-core-10.3", ver: "1:10.3.20-0ubuntu0.19.10.1", rls: "UBUNTU19.10" ) )){
		report += res;
	}
	if(!isnull( res = isdpkgvuln( pkg: "mariadb-common", ver: "1:10.3.20-0ubuntu0.19.10.1", rls: "UBUNTU19.10" ) )){
		report += res;
	}
	if(!isnull( res = isdpkgvuln( pkg: "mariadb-plugin-connect", ver: "1:10.3.20-0ubuntu0.19.10.1", rls: "UBUNTU19.10" ) )){
		report += res;
	}
	if(!isnull( res = isdpkgvuln( pkg: "mariadb-plugin-cracklib-password-check", ver: "1:10.3.20-0ubuntu0.19.10.1", rls: "UBUNTU19.10" ) )){
		report += res;
	}
	if(!isnull( res = isdpkgvuln( pkg: "mariadb-plugin-gssapi-client", ver: "1:10.3.20-0ubuntu0.19.10.1", rls: "UBUNTU19.10" ) )){
		report += res;
	}
	if(!isnull( res = isdpkgvuln( pkg: "mariadb-plugin-gssapi-server", ver: "1:10.3.20-0ubuntu0.19.10.1", rls: "UBUNTU19.10" ) )){
		report += res;
	}
	if(!isnull( res = isdpkgvuln( pkg: "mariadb-plugin-mroonga", ver: "1:10.3.20-0ubuntu0.19.10.1", rls: "UBUNTU19.10" ) )){
		report += res;
	}
	if(!isnull( res = isdpkgvuln( pkg: "mariadb-plugin-oqgraph", ver: "1:10.3.20-0ubuntu0.19.10.1", rls: "UBUNTU19.10" ) )){
		report += res;
	}
	if(!isnull( res = isdpkgvuln( pkg: "mariadb-plugin-rocksdb", ver: "1:10.3.20-0ubuntu0.19.10.1", rls: "UBUNTU19.10" ) )){
		report += res;
	}
	if(!isnull( res = isdpkgvuln( pkg: "mariadb-plugin-spider", ver: "1:10.3.20-0ubuntu0.19.10.1", rls: "UBUNTU19.10" ) )){
		report += res;
	}
	if(!isnull( res = isdpkgvuln( pkg: "mariadb-plugin-tokudb", ver: "1:10.3.20-0ubuntu0.19.10.1", rls: "UBUNTU19.10" ) )){
		report += res;
	}
	if(!isnull( res = isdpkgvuln( pkg: "mariadb-server", ver: "1:10.3.20-0ubuntu0.19.10.1", rls: "UBUNTU19.10" ) )){
		report += res;
	}
	if(!isnull( res = isdpkgvuln( pkg: "mariadb-server-10.3", ver: "1:10.3.20-0ubuntu0.19.10.1", rls: "UBUNTU19.10" ) )){
		report += res;
	}
	if(!isnull( res = isdpkgvuln( pkg: "mariadb-server-core-10.3", ver: "1:10.3.20-0ubuntu0.19.10.1", rls: "UBUNTU19.10" ) )){
		report += res;
	}
	if(!isnull( res = isdpkgvuln( pkg: "mariadb-test", ver: "1:10.3.20-0ubuntu0.19.10.1", rls: "UBUNTU19.10" ) )){
		report += res;
	}
	if(!isnull( res = isdpkgvuln( pkg: "mariadb-test-data", ver: "1:10.3.20-0ubuntu0.19.10.1", rls: "UBUNTU19.10" ) )){
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
}
if(release == "UBUNTU19.04"){
	if(!isnull( res = isdpkgvuln( pkg: "libmariadb-dev", ver: "1:10.3.20-0ubuntu0.19.04.1", rls: "UBUNTU19.04" ) )){
		report += res;
	}
	if(!isnull( res = isdpkgvuln( pkg: "libmariadb-dev-compat", ver: "1:10.3.20-0ubuntu0.19.04.1", rls: "UBUNTU19.04" ) )){
		report += res;
	}
	if(!isnull( res = isdpkgvuln( pkg: "libmariadb3", ver: "1:10.3.20-0ubuntu0.19.04.1", rls: "UBUNTU19.04" ) )){
		report += res;
	}
	if(!isnull( res = isdpkgvuln( pkg: "libmariadbclient-dev", ver: "1:10.3.20-0ubuntu0.19.04.1", rls: "UBUNTU19.04" ) )){
		report += res;
	}
	if(!isnull( res = isdpkgvuln( pkg: "libmariadbd-dev", ver: "1:10.3.20-0ubuntu0.19.04.1", rls: "UBUNTU19.04" ) )){
		report += res;
	}
	if(!isnull( res = isdpkgvuln( pkg: "libmariadbd19", ver: "1:10.3.20-0ubuntu0.19.04.1", rls: "UBUNTU19.04" ) )){
		report += res;
	}
	if(!isnull( res = isdpkgvuln( pkg: "mariadb-backup", ver: "1:10.3.20-0ubuntu0.19.04.1", rls: "UBUNTU19.04" ) )){
		report += res;
	}
	if(!isnull( res = isdpkgvuln( pkg: "mariadb-client", ver: "1:10.3.20-0ubuntu0.19.04.1", rls: "UBUNTU19.04" ) )){
		report += res;
	}
	if(!isnull( res = isdpkgvuln( pkg: "mariadb-client-10.3", ver: "1:10.3.20-0ubuntu0.19.04.1", rls: "UBUNTU19.04" ) )){
		report += res;
	}
	if(!isnull( res = isdpkgvuln( pkg: "mariadb-client-core-10.3", ver: "1:10.3.20-0ubuntu0.19.04.1", rls: "UBUNTU19.04" ) )){
		report += res;
	}
	if(!isnull( res = isdpkgvuln( pkg: "mariadb-common", ver: "1:10.3.20-0ubuntu0.19.04.1", rls: "UBUNTU19.04" ) )){
		report += res;
	}
	if(!isnull( res = isdpkgvuln( pkg: "mariadb-plugin-connect", ver: "1:10.3.20-0ubuntu0.19.04.1", rls: "UBUNTU19.04" ) )){
		report += res;
	}
	if(!isnull( res = isdpkgvuln( pkg: "mariadb-plugin-cracklib-password-check", ver: "1:10.3.20-0ubuntu0.19.04.1", rls: "UBUNTU19.04" ) )){
		report += res;
	}
	if(!isnull( res = isdpkgvuln( pkg: "mariadb-plugin-gssapi-client", ver: "1:10.3.20-0ubuntu0.19.04.1", rls: "UBUNTU19.04" ) )){
		report += res;
	}
	if(!isnull( res = isdpkgvuln( pkg: "mariadb-plugin-gssapi-server", ver: "1:10.3.20-0ubuntu0.19.04.1", rls: "UBUNTU19.04" ) )){
		report += res;
	}
	if(!isnull( res = isdpkgvuln( pkg: "mariadb-plugin-mroonga", ver: "1:10.3.20-0ubuntu0.19.04.1", rls: "UBUNTU19.04" ) )){
		report += res;
	}
	if(!isnull( res = isdpkgvuln( pkg: "mariadb-plugin-oqgraph", ver: "1:10.3.20-0ubuntu0.19.04.1", rls: "UBUNTU19.04" ) )){
		report += res;
	}
	if(!isnull( res = isdpkgvuln( pkg: "mariadb-plugin-rocksdb", ver: "1:10.3.20-0ubuntu0.19.04.1", rls: "UBUNTU19.04" ) )){
		report += res;
	}
	if(!isnull( res = isdpkgvuln( pkg: "mariadb-plugin-spider", ver: "1:10.3.20-0ubuntu0.19.04.1", rls: "UBUNTU19.04" ) )){
		report += res;
	}
	if(!isnull( res = isdpkgvuln( pkg: "mariadb-plugin-tokudb", ver: "1:10.3.20-0ubuntu0.19.04.1", rls: "UBUNTU19.04" ) )){
		report += res;
	}
	if(!isnull( res = isdpkgvuln( pkg: "mariadb-server", ver: "1:10.3.20-0ubuntu0.19.04.1", rls: "UBUNTU19.04" ) )){
		report += res;
	}
	if(!isnull( res = isdpkgvuln( pkg: "mariadb-server-10.3", ver: "1:10.3.20-0ubuntu0.19.04.1", rls: "UBUNTU19.04" ) )){
		report += res;
	}
	if(!isnull( res = isdpkgvuln( pkg: "mariadb-server-core-10.3", ver: "1:10.3.20-0ubuntu0.19.04.1", rls: "UBUNTU19.04" ) )){
		report += res;
	}
	if(!isnull( res = isdpkgvuln( pkg: "mariadb-test", ver: "1:10.3.20-0ubuntu0.19.04.1", rls: "UBUNTU19.04" ) )){
		report += res;
	}
	if(!isnull( res = isdpkgvuln( pkg: "mariadb-test-data", ver: "1:10.3.20-0ubuntu0.19.04.1", rls: "UBUNTU19.04" ) )){
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
}
exit( 0 );

