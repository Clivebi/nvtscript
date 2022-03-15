if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.71253" );
	script_cve_id( "CVE-2012-0805" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_version( "$Revision: 14275 $" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-18 15:39:45 +0100 (Mon, 18 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2012-04-30 07:56:14 -0400 (Mon, 30 Apr 2012)" );
	script_name( "Debian Security Advisory DSA 2449-1 (sqlalchemy)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2012 E-Soft Inc. http://www.securityspace.com" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB(6|7)" );
	script_xref( name: "URL", value: "https://secure1.securityspace.com/smysecure/catid.html?in=DSA%202449-1" );
	script_tag( name: "insight", value: "It was discovered that sqlalchemy, an SQL toolkit and object relational
mapper for python, is not sanitizing input passed to the limit/offset
keywords to select() as well as the value passed to select.limit()/offset().
This allows an attacker to perform SQL injection attacks against
applications using sqlalchemy that do not implement their own filtering.

For the stable distribution (squeeze), this problem has been fixed in
version 0.6.3-3+squeeze1.

For the testing distribution (wheezy), this problem has been fixed in
version 0.6.7-1.

For the unstable distribution (sid), this problem has been fixed in
version 0.6.7-1." );
	script_tag( name: "solution", value: "We recommend that you upgrade your sqlalchemy packages." );
	script_tag( name: "summary", value: "The remote host is missing an update to sqlalchemy
announced via advisory DSA 2449-1." );
	script_tag( name: "qod_type", value: "package" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(( res = isdpkgvuln( pkg: "python-sqlalchemy", ver: "0.6.3-3+squeeze1", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "python-sqlalchemy-doc", ver: "0.6.3-3+squeeze1", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "python-sqlalchemy-ext", ver: "0.6.3-3+squeeze1", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "python3-sqlalchemy", ver: "0.6.3-3+squeeze1", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "python-sqlalchemy", ver: "0.7.6-1", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "python-sqlalchemy-doc", ver: "0.7.6-1", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "python-sqlalchemy-ext", ver: "0.7.6-1", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "python3-sqlalchemy", ver: "0.7.6-1", rls: "DEB7" ) ) != NULL){
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

