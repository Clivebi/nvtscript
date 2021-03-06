if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.703646" );
	script_version( "2021-09-20T14:01:48+0000" );
	script_cve_id( "CVE-2016-5423", "CVE-2016-5424" );
	script_name( "Debian Security Advisory DSA 3646-1 (postgresql-9.4 - security update)" );
	script_tag( name: "last_modification", value: "2021-09-20 14:01:48 +0000 (Mon, 20 Sep 2021)" );
	script_tag( name: "creation_date", value: "2016-08-11 00:00:00 +0200 (Thu, 11 Aug 2016)" );
	script_tag( name: "cvss_base", value: "6.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:S/C:P/I:P/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2018-01-05 02:31:00 +0000 (Fri, 05 Jan 2018)" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	script_xref( name: "URL", value: "http://www.debian.org/security/2016/dsa-3646.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2016 Greenbone Networks GmbH" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB8" );
	script_tag( name: "affected", value: "postgresql-9.4 on Debian Linux" );
	script_tag( name: "solution", value: "For the stable distribution (jessie),
these problems have been fixed in version 9.4.9-0+deb8u1.

We recommend that you upgrade your postgresql-9.4 packages." );
	script_tag( name: "summary", value: "Several vulnerabilities have been
found in PostgreSQL-9.4, a SQL database system.

CVE-2016-5423
Karthikeyan Jambu Rajaraman discovered that nested CASE-WHEN
expressions are not properly evaluated, potentially leading to a
crash or allowing to disclose portions of server memory.

CVE-2016-5424
Nathan Bossart discovered that special characters in database and
role names are not properly handled, potentially leading to the
execution of commands with superuser privileges, when a superuser
executes pg_dumpall or other routine maintenance operations." );
	script_tag( name: "vuldetect", value: "This check tests the installed
software version using the apt package manager." );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(( res = isdpkgvuln( pkg: "libecpg-compat3:amd64", ver: "9.4.9-0+deb8u1", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libecpg-compat3:i386", ver: "9.4.9-0+deb8u1", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libecpg-dev", ver: "9.4.9-0+deb8u1", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libecpg6:amd64", ver: "9.4.9-0+deb8u1", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libecpg6:i386", ver: "9.4.9-0+deb8u1", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libpgtypes3:amd64", ver: "9.4.9-0+deb8u1", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libpgtypes3:i386", ver: "9.4.9-0+deb8u1", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libpq-dev", ver: "9.4.9-0+deb8u1", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libpq5:amd64", ver: "9.4.9-0+deb8u1", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libpq5:i386", ver: "9.4.9-0+deb8u1", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "postgresql-9.4", ver: "9.4.9-0+deb8u1", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "postgresql-9.4-dbg", ver: "9.4.9-0+deb8u1", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "postgresql-client-9.4", ver: "9.4.9-0+deb8u1", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "postgresql-contrib-9.4", ver: "9.4.9-0+deb8u1", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "postgresql-doc-9.4", ver: "9.4.9-0+deb8u1", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "postgresql-plperl-9.4", ver: "9.4.9-0+deb8u1", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "postgresql-plpython-9.4", ver: "9.4.9-0+deb8u1", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "postgresql-plpython3-9.4", ver: "9.4.9-0+deb8u1", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "postgresql-pltcl-9.4", ver: "9.4.9-0+deb8u1", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "postgresql-server-dev-9.4", ver: "9.4.9-0+deb8u1", rls: "DEB8" ) ) != NULL){
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

