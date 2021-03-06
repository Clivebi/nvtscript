if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.703767" );
	script_version( "2021-09-20T13:38:59+0000" );
	script_cve_id( "CVE-2017-3238", "CVE-2017-3243", "CVE-2017-3244", "CVE-2017-3258", "CVE-2017-3265", "CVE-2017-3291", "CVE-2017-3312", "CVE-2017-3313", "CVE-2017-3317", "CVE-2017-3318" );
	script_name( "Debian Security Advisory DSA 3767-1 (mysql-5.5 - security update)" );
	script_tag( name: "last_modification", value: "2021-09-20 13:38:59 +0000 (Mon, 20 Sep 2021)" );
	script_tag( name: "creation_date", value: "2017-01-19 00:00:00 +0100 (Thu, 19 Jan 2017)" );
	script_tag( name: "cvss_base", value: "4.9" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:S/C:P/I:N/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:L/AC:H/PR:H/UI:R/S:U/C:H/I:N/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-10-03 00:03:00 +0000 (Thu, 03 Oct 2019)" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	script_xref( name: "URL", value: "http://www.debian.org/security/2017/dsa-3767.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2017 Greenbone Networks GmbH" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB8" );
	script_tag( name: "affected", value: "mysql-5.5 on Debian Linux" );
	script_tag( name: "solution", value: "For the stable distribution (jessie),
these problems have been fixed in version 5.5.54-0+deb8u1.

We recommend that you upgrade your mysql-5.5 packages." );
	script_tag( name: "summary", value: "Several issues have been discovered in
the MySQL database server. The vulnerabilities are addressed by upgrading MySQL to
the new upstream version 5.5.54, which includes additional changes, such as
performance improvements, bug fixes, new features, and possibly incompatible
changes." );
	script_tag( name: "vuldetect", value: "This check tests the installed software
version using the apt package manager." );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(( res = isdpkgvuln( pkg: "libmysqlclient-dev", ver: "5.5.54-0+deb8u1", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libmysqlclient18:amd64", ver: "5.5.54-0+deb8u1", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libmysqlclient18:i386", ver: "5.5.54-0+deb8u1", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libmysqld-dev", ver: "5.5.54-0+deb8u1", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libmysqld-pic", ver: "5.5.54-0+deb8u1", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "mysql-client", ver: "5.5.54-0+deb8u1", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "mysql-client-5.5", ver: "5.5.54-0+deb8u1", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "mysql-common", ver: "5.5.54-0+deb8u1", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "mysql-server", ver: "5.5.54-0+deb8u1", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "mysql-server-5.5", ver: "5.5.54-0+deb8u1", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "mysql-server-core-5.5", ver: "5.5.54-0+deb8u1", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "mysql-source-5.5", ver: "5.5.54-0+deb8u1", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "mysql-testsuite", ver: "5.5.54-0+deb8u1", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "mysql-testsuite-5.5", ver: "5.5.54-0+deb8u1", rls: "DEB8" ) ) != NULL){
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

