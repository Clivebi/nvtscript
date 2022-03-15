if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.891566" );
	script_version( "2021-06-17T02:00:27+0000" );
	script_cve_id( "CVE-2018-2767", "CVE-2018-3058", "CVE-2018-3063", "CVE-2018-3066", "CVE-2018-3070", "CVE-2018-3081", "CVE-2018-3133", "CVE-2018-3174", "CVE-2018-3282" );
	script_name( "Debian LTS: Security Advisory for mysql-5.5 (DLA-1566-1)" );
	script_tag( name: "last_modification", value: "2021-06-17 02:00:27 +0000 (Thu, 17 Jun 2021)" );
	script_tag( name: "creation_date", value: "2018-11-06 00:00:00 +0100 (Tue, 06 Nov 2018)" );
	script_tag( name: "cvss_base", value: "4.9" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:S/C:P/I:P/A:N" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:H/PR:H/UI:N/S:U/C:L/I:L/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-10-03 00:03:00 +0000 (Thu, 03 Oct 2019)" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	script_xref( name: "URL", value: "https://lists.debian.org/debian-lts-announce/2018/11/msg00004.html" );
	script_xref( name: "URL", value: "https://dev.mysql.com/doc/relnotes/mysql/5.5/en/news-5-5-61.html" );
	script_xref( name: "URL", value: "https://www.oracle.com/technetwork/security-advisory/cpujul2018-4258247.html" );
	script_xref( name: "URL", value: "https://dev.mysql.com/doc/relnotes/mysql/5.5/en/news-5-5-62.html" );
	script_xref( name: "URL", value: "https://www.oracle.com/technetwork/security-advisory/cpuoct2018-4428296.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH http://greenbone.net" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB8" );
	script_tag( name: "affected", value: "mysql-5.5 on Debian Linux" );
	script_tag( name: "solution", value: "For Debian 8 'Jessie', these problems have been fixed in version
5.5.62-0+deb8u1.

We recommend that you upgrade your mysql-5.5 packages." );
	script_tag( name: "summary", value: "Several issues have been discovered in the MySQL database server. The
vulnerabilities are addressed by upgrading MySQL to the new upstream
version 5.5.62, which includes additional changes. Please see the MySQL
5.5 Release Notes and Oracle's Critical Patch Update advisory for
further details." );
	script_tag( name: "vuldetect", value: "This check tests the installed software version using the apt package manager." );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(!isnull( res = isdpkgvuln( pkg: "libmysqlclient-dev", ver: "5.5.62-0+deb8u1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libmysqlclient18", ver: "5.5.62-0+deb8u1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libmysqld-dev", ver: "5.5.62-0+deb8u1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libmysqld-pic", ver: "5.5.62-0+deb8u1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "mysql-client", ver: "5.5.62-0+deb8u1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "mysql-client-5.5", ver: "5.5.62-0+deb8u1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "mysql-common", ver: "5.5.62-0+deb8u1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "mysql-server", ver: "5.5.62-0+deb8u1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "mysql-server-5.5", ver: "5.5.62-0+deb8u1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "mysql-server-core-5.5", ver: "5.5.62-0+deb8u1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "mysql-source-5.5", ver: "5.5.62-0+deb8u1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "mysql-testsuite", ver: "5.5.62-0+deb8u1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "mysql-testsuite-5.5", ver: "5.5.62-0+deb8u1", rls: "DEB8" ) )){
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

