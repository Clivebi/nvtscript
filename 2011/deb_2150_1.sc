if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.68988" );
	script_version( "$Revision: 14275 $" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-18 15:39:45 +0100 (Mon, 18 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2011-03-07 16:04:02 +0100 (Mon, 07 Mar 2011)" );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:N/A:N" );
	script_cve_id( "CVE-2011-0009" );
	script_name( "Debian Security Advisory DSA 2150-1 (request-tracker3.6)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2011 E-Soft Inc. http://www.securityspace.com" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB5" );
	script_xref( name: "URL", value: "https://secure1.securityspace.com/smysecure/catid.html?in=DSA%202150-1" );
	script_tag( name: "insight", value: "It was discovered that Request Tracker, an issue tracking system,
stored passwords in its database by using an insufficiently strong
hashing method. If an attacker would have access to the password
database, he could decode the passwords stored in it.

For the stable distribution (lenny), this problem has been fixed in
version 3.6.7-5+lenny5.

The testing distribution (squeeze) will be fixed soon.

For the unstable distribution (sid), this problem has been fixed in
version 3.8.8-7 of the request-tracker3.8 package." );
	script_tag( name: "solution", value: "We recommend that you upgrade your Request Tracker packages." );
	script_tag( name: "summary", value: "The remote host is missing an update to request-tracker3.6
announced via advisory DSA 2150-1." );
	script_tag( name: "qod_type", value: "package" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(( res = isdpkgvuln( pkg: "request-tracker3.6", ver: "3.6.7-5+lenny5", rls: "DEB5" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "rt3.6-apache2", ver: "3.6.7-5+lenny5", rls: "DEB5" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "rt3.6-clients", ver: "3.6.7-5+lenny5", rls: "DEB5" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "rt3.6-db-mysql", ver: "3.6.7-5+lenny5", rls: "DEB5" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "rt3.6-db-postgresql", ver: "3.6.7-5+lenny5", rls: "DEB5" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "rt3.6-db-sqlite", ver: "3.6.7-5+lenny5", rls: "DEB5" ) ) != NULL){
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

