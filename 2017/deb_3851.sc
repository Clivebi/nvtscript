if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.703851" );
	script_version( "2021-09-15T11:15:39+0000" );
	script_cve_id( "CVE-2017-7484", "CVE-2017-7485", "CVE-2017-7486" );
	script_name( "Debian Security Advisory DSA 3851-1 (postgresql-9.4 - security update)" );
	script_tag( name: "last_modification", value: "2021-09-15 11:15:39 +0000 (Wed, 15 Sep 2021)" );
	script_tag( name: "creation_date", value: "2017-05-12 00:00:00 +0200 (Fri, 12 May 2017)" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:N/A:N" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2018-01-05 02:31:00 +0000 (Fri, 05 Jan 2018)" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	script_xref( name: "URL", value: "http://www.debian.org/security/2017/dsa-3851.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2017 Greenbone Networks GmbH" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB8" );
	script_tag( name: "affected", value: "postgresql-9.4 on Debian Linux" );
	script_tag( name: "solution", value: "For the stable distribution (jessie), these problems have been fixed in
version 9.4.12-0+deb8u1.

We recommend that you upgrade your postgresql-9.4 packages." );
	script_tag( name: "summary", value: "Several vulnerabilities have been found in the PostgreSQL database
system:

CVE-2017-7484
Robert Haas discovered that some selectivity estimators did not
validate user privileges which could result in information
disclosure.

CVE-2017-7485
Daniel Gustafsson discovered that the PGREQUIRESSL environment
variable did no longer enforce a TLS connection.

CVE-2017-7486
Andrew Wheelwright discovered that user mappings were insufficiently
restricted." );
	script_tag( name: "vuldetect", value: "This check tests the installed software version using the apt package manager." );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(( res = isdpkgvuln( pkg: "libecpg-compat3", ver: "9.4.12-0+deb8u1", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libecpg-dev", ver: "9.4.12-0+deb8u1", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libecpg6", ver: "9.4.12-0+deb8u1", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libpgtypes3", ver: "9.4.12-0+deb8u1", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libpq-dev", ver: "9.4.12-0+deb8u1", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libpq5", ver: "9.4.12-0+deb8u1", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "postgresql-9.4", ver: "9.4.12-0+deb8u1", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "postgresql-9.4-dbg", ver: "9.4.12-0+deb8u1", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "postgresql-client-9.4", ver: "9.4.12-0+deb8u1", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "postgresql-contrib-9.4", ver: "9.4.12-0+deb8u1", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "postgresql-doc-9.4", ver: "9.4.12-0+deb8u1", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "postgresql-plperl-9.4", ver: "9.4.12-0+deb8u1", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "postgresql-plpython-9.4", ver: "9.4.12-0+deb8u1", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "postgresql-plpython3-9.4", ver: "9.4.12-0+deb8u1", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "postgresql-pltcl-9.4", ver: "9.4.12-0+deb8u1", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "postgresql-server-dev-9.4", ver: "9.4.12-0+deb8u1", rls: "DEB8" ) ) != NULL){
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

