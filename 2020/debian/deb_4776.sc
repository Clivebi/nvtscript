if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.704776" );
	script_version( "2021-07-23T11:01:09+0000" );
	script_cve_id( "CVE-2020-15180" );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2021-07-23 11:01:09 +0000 (Fri, 23 Jul 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:C/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-06-10 14:50:00 +0000 (Thu, 10 Jun 2021)" );
	script_tag( name: "creation_date", value: "2020-10-22 03:00:13 +0000 (Thu, 22 Oct 2020)" );
	script_name( "Debian: Security Advisory for mariadb-10.3 (DSA-4776-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB10" );
	script_xref( name: "URL", value: "https://www.debian.org/security/2020/dsa-4776.html" );
	script_xref( name: "URL", value: "https://security-tracker.debian.org/tracker/DSA-4776-1" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'mariadb-10.3'
  package(s) announced via the DSA-4776-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "A security issue was discovered in the MariaDB database server." );
	script_tag( name: "affected", value: "'mariadb-10.3' package(s) on Debian Linux." );
	script_tag( name: "solution", value: "For the stable distribution (buster), this problem has been fixed in
version 1:10.3.25-0+deb10u1.

We recommend that you upgrade your mariadb-10.3 packages." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(!isnull( res = isdpkgvuln( pkg: "libmariadb-dev", ver: "1:10.3.25-0+deb10u1", rls: "DEB10" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libmariadb-dev-compat", ver: "1:10.3.25-0+deb10u1", rls: "DEB10" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libmariadb3", ver: "1:10.3.25-0+deb10u1", rls: "DEB10" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libmariadbclient-dev", ver: "1:10.3.25-0+deb10u1", rls: "DEB10" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libmariadbd-dev", ver: "1:10.3.25-0+deb10u1", rls: "DEB10" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libmariadbd19", ver: "1:10.3.25-0+deb10u1", rls: "DEB10" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "mariadb-backup", ver: "1:10.3.25-0+deb10u1", rls: "DEB10" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "mariadb-client", ver: "1:10.3.25-0+deb10u1", rls: "DEB10" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "mariadb-client-10.3", ver: "1:10.3.25-0+deb10u1", rls: "DEB10" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "mariadb-client-core-10.3", ver: "1:10.3.25-0+deb10u1", rls: "DEB10" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "mariadb-common", ver: "1:10.3.25-0+deb10u1", rls: "DEB10" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "mariadb-plugin-connect", ver: "1:10.3.25-0+deb10u1", rls: "DEB10" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "mariadb-plugin-cracklib-password-check", ver: "1:10.3.25-0+deb10u1", rls: "DEB10" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "mariadb-plugin-gssapi-client", ver: "1:10.3.25-0+deb10u1", rls: "DEB10" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "mariadb-plugin-gssapi-server", ver: "1:10.3.25-0+deb10u1", rls: "DEB10" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "mariadb-plugin-mroonga", ver: "1:10.3.25-0+deb10u1", rls: "DEB10" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "mariadb-plugin-oqgraph", ver: "1:10.3.25-0+deb10u1", rls: "DEB10" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "mariadb-plugin-rocksdb", ver: "1:10.3.25-0+deb10u1", rls: "DEB10" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "mariadb-plugin-spider", ver: "1:10.3.25-0+deb10u1", rls: "DEB10" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "mariadb-plugin-tokudb", ver: "1:10.3.25-0+deb10u1", rls: "DEB10" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "mariadb-server", ver: "1:10.3.25-0+deb10u1", rls: "DEB10" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "mariadb-server-10.3", ver: "1:10.3.25-0+deb10u1", rls: "DEB10" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "mariadb-server-core-10.3", ver: "1:10.3.25-0+deb10u1", rls: "DEB10" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "mariadb-test", ver: "1:10.3.25-0+deb10u1", rls: "DEB10" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "mariadb-test-data", ver: "1:10.3.25-0+deb10u1", rls: "DEB10" ) )){
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

