if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.702657" );
	script_version( "2020-10-05T06:02:24+0000" );
	script_cve_id( "CVE-2013-1899", "CVE-2013-1900", "CVE-2013-1901" );
	script_name( "Debian Security Advisory DSA 2657-1 (postgresql-8.4 - guessable random numbers)" );
	script_tag( name: "last_modification", value: "2020-10-05 06:02:24 +0000 (Mon, 05 Oct 2020)" );
	script_tag( name: "creation_date", value: "2013-04-04 00:00:00 +0200 (Thu, 04 Apr 2013)" );
	script_tag( name: "cvss_base", value: "8.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:S/C:C/I:C/A:C" );
	script_xref( name: "URL", value: "http://www.debian.org/security/2013/dsa-2657.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2013 Greenbone Networks GmbH http://greenbone.net" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB6" );
	script_tag( name: "affected", value: "postgresql-8.4 on Debian Linux" );
	script_tag( name: "solution", value: "For the stable distribution (squeeze), this problem has been fixed in
version 8.4.17-0squeeze1.

For the testing (wheezy) and unstable distribution (sid), postgresql-8.4
packages have been removed. In those, this problem has been fixed in
postgresql-9.1 9.1.9-0wheezy1 (wheezy), and 9.1.9-1 (sid) respectively.

Note: postgresql-8.4 in Squeeze is not affected by CVE-2013-1899 (database files corruption) and CVE-2013-1901

(unprivileged user can interfere with in-progress backups).

We recommend that you upgrade your postgresql-8.4 packages." );
	script_tag( name: "summary", value: "A vulnerability was discovered in PostgreSQL database server.
Random numbers generated by contrib/pgcrypto functions may be easy
for another database user to guess." );
	script_tag( name: "vuldetect", value: "This check tests the installed software version using the apt package manager." );
	script_tag( name: "qod_type", value: "package" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(( res = isdpkgvuln( pkg: "libecpg-compat3", ver: "8.4.17-0squeeze1", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libecpg-dev", ver: "8.4.17-0squeeze1", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libecpg6", ver: "8.4.17-0squeeze1", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libpgtypes3", ver: "8.4.17-0squeeze1", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libpq-dev", ver: "8.4.17-0squeeze1", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libpq5", ver: "8.4.17-0squeeze1", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "postgresql", ver: "8.4.17-0squeeze1", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "postgresql-8.4", ver: "8.4.17-0squeeze1", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "postgresql-client", ver: "8.4.17-0squeeze1", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "postgresql-client-8.4", ver: "8.4.17-0squeeze1", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "postgresql-contrib", ver: "8.4.17-0squeeze1", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "postgresql-contrib-8.4", ver: "8.4.17-0squeeze1", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "postgresql-doc", ver: "8.4.17-0squeeze1", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "postgresql-doc-8.4", ver: "8.4.17-0squeeze1", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "postgresql-plperl-8.4", ver: "8.4.17-0squeeze1", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "postgresql-plpython-8.4", ver: "8.4.17-0squeeze1", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "postgresql-pltcl-8.4", ver: "8.4.17-0squeeze1", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "postgresql-server-dev-8.4", ver: "8.4.17-0squeeze1", rls: "DEB6" ) ) != NULL){
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

