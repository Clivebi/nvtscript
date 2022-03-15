if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.703595" );
	script_version( "2021-09-20T13:38:59+0000" );
	script_cve_id( "CVE-2016-0640", "CVE-2016-0641", "CVE-2016-0643", "CVE-2016-0644", "CVE-2016-0646", "CVE-2016-0647", "CVE-2016-0648", "CVE-2016-0649", "CVE-2016-0650", "CVE-2016-0655", "CVE-2016-0666", "CVE-2016-0668" );
	script_name( "Debian Security Advisory DSA 3595-1 (mariadb-10.0 - security update)" );
	script_tag( name: "last_modification", value: "2021-09-20 13:38:59 +0000 (Mon, 20 Sep 2021)" );
	script_tag( name: "creation_date", value: "2016-06-05 00:00:00 +0200 (Sun, 05 Jun 2016)" );
	script_tag( name: "cvss_base", value: "4.9" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:S/C:N/I:P/A:P" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	script_xref( name: "URL", value: "http://www.debian.org/security/2016/dsa-3595.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2016 Greenbone Networks GmbH" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB8" );
	script_tag( name: "affected", value: "mariadb-10.0 on Debian Linux" );
	script_tag( name: "solution", value: "For the stable distribution (jessie),
these problems have been fixed in version 10.0.25-0+deb8u1.

We recommend that you upgrade your mariadb-10.0 packages." );
	script_tag( name: "summary", value: "Several issues have been discovered
in the MariaDB database server. The vulnerabilities are addressed by upgrading
MariaDB to the new upstream version 10.0.25." );
	script_tag( name: "vuldetect", value: "This check tests the installed software
version using the apt package manager." );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(( res = isdpkgvuln( pkg: "libmariadbd-dev", ver: "10.0.25-0+deb8u1", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "mariadb-client", ver: "10.0.25-0+deb8u1", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "mariadb-client-10.0", ver: "10.0.25-0+deb8u1", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "mariadb-client-core-10.0", ver: "10.0.25-0+deb8u1", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "mariadb-common", ver: "10.0.25-0+deb8u1", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "mariadb-connect-engine-10.0", ver: "10.0.25-0+deb8u1", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "mariadb-oqgraph-engine-10.0", ver: "10.0.25-0+deb8u1", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "mariadb-server", ver: "10.0.25-0+deb8u1", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "mariadb-server-10.0", ver: "10.0.25-0+deb8u1", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "mariadb-server-core-10.0", ver: "10.0.25-0+deb8u1", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "mariadb-test", ver: "10.0.25-0+deb8u1", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "mariadb-test-10.0", ver: "10.0.25-0+deb8u1", rls: "DEB8" ) ) != NULL){
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

