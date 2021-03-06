if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.71146" );
	script_cve_id( "CVE-2012-0866", "CVE-2012-0867", "CVE-2012-0868" );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_version( "$Revision: 14275 $" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-18 15:39:45 +0100 (Mon, 18 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2012-03-12 11:32:17 -0400 (Mon, 12 Mar 2012)" );
	script_name( "Debian Security Advisory DSA 2418-1 (postgresql-8.4)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2012 E-Soft Inc. http://www.securityspace.com" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB6" );
	script_xref( name: "URL", value: "https://secure1.securityspace.com/smysecure/catid.html?in=DSA%202418-1" );
	script_tag( name: "insight", value: "Several local vulnerabilities have been discovered in PostgreSQL, an
object-relational SQL database. The Common Vulnerabilities and Exposures
project identifies the following problems:

CVE-2012-0866

It was discovered that the permissions of a function called by a
trigger are not checked. This could result in privilege escalation.

CVE-2012-0867

It was discovered that only the first 32 characters of a host name
are checked when validating host names through SSL certificates.
This could result in spoofing the connection in limited
circumstances.

CVE-2012-0868

It was discovered that pg_dump did not sanitise object names.
This could result in arbitrary SQL command execution if a
malformed dump file is opened.

For the stable distribution (squeeze), this problem has been fixed in
version 8.4.11-0squeeze1.

For the unstable distribution (sid), this problem has been fixed in
version 8.4.11-1." );
	script_tag( name: "solution", value: "We recommend that you upgrade your postgresql-8.4 packages." );
	script_tag( name: "summary", value: "The remote host is missing an update to postgresql-8.4
announced via advisory DSA 2418-1." );
	script_tag( name: "qod_type", value: "package" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(( res = isdpkgvuln( pkg: "libecpg-compat3", ver: "8.4.11-0squeeze1", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libecpg-dev", ver: "8.4.11-0squeeze1", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libecpg6", ver: "8.4.11-0squeeze1", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libpgtypes3", ver: "8.4.11-0squeeze1", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libpq-dev", ver: "8.4.11-0squeeze1", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libpq5", ver: "8.4.11-0squeeze1", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "postgresql", ver: "8.4.11-0squeeze1", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "postgresql-8.4", ver: "8.4.11-0squeeze1", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "postgresql-client", ver: "8.4.11-0squeeze1", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "postgresql-client-8.4", ver: "8.4.11-0squeeze1", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "postgresql-contrib", ver: "8.4.11-0squeeze1", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "postgresql-contrib-8.4", ver: "8.4.11-0squeeze1", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "postgresql-doc", ver: "8.4.11-0squeeze1", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "postgresql-doc-8.4", ver: "8.4.11-0squeeze1", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "postgresql-plperl-8.4", ver: "8.4.11-0squeeze1", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "postgresql-plpython-8.4", ver: "8.4.11-0squeeze1", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "postgresql-pltcl-8.4", ver: "8.4.11-0squeeze1", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "postgresql-server-dev-8.4", ver: "8.4.11-0squeeze1", rls: "DEB6" ) ) != NULL){
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

