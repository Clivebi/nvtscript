if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.69116" );
	script_version( "$Revision: 14275 $" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-18 15:39:45 +0100 (Mon, 18 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2011-03-09 05:54:11 +0100 (Wed, 09 Mar 2011)" );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:N/A:P" );
	script_cve_id( "CVE-2011-0715" );
	script_name( "Debian Security Advisory DSA 2181-1 (subversion)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2011 E-Soft Inc. http://www.securityspace.com" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB(5|6|7)" );
	script_tag( name: "insight", value: "Philip Martin discovered that HTTP-based Subversion servers crash when
processing lock requests on repositories which support unauthenticated
read access." );
	script_tag( name: "summary", value: "The remote host is missing an update to subversion
announced via advisory DSA 2181-1." );
	script_tag( name: "solution", value: "For the oldstable distribution (lenny), this problem has been fixed in
version 1.5.1dfsg1-6.

For the stable distribution (squeeze), this problem has been fixed in
version 1.6.12dfsg-5.

For the testing distribution (wheezy) and the unstable distribution
(sid), this problem will be fixed in version 1.6.16dfsg-1.

We recommend that you upgrade your subversion packages." );
	script_xref( name: "URL", value: "https://secure1.securityspace.com/smysecure/catid.html?in=DSA%202181-1" );
	script_tag( name: "qod_type", value: "package" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(( res = isdpkgvuln( pkg: "libapache2-svn", ver: "1.5.1dfsg1-6", rls: "DEB5" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libsvn-dev", ver: "1.5.1dfsg1-6", rls: "DEB5" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libsvn-doc", ver: "1.5.1dfsg1-6", rls: "DEB5" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libsvn-java", ver: "1.5.1dfsg1-6", rls: "DEB5" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libsvn-perl", ver: "1.5.1dfsg1-6", rls: "DEB5" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libsvn-ruby", ver: "1.5.1dfsg1-6", rls: "DEB5" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libsvn-ruby1.8", ver: "1.5.1dfsg1-6", rls: "DEB5" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libsvn1", ver: "1.5.1dfsg1-6", rls: "DEB5" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "python-subversion", ver: "1.5.1dfsg1-6", rls: "DEB5" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "subversion", ver: "1.5.1dfsg1-6", rls: "DEB5" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "subversion-tools", ver: "1.5.1dfsg1-6", rls: "DEB5" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libapache2-svn", ver: "1.6.12dfsg-5", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libsvn-dev", ver: "1.6.12dfsg-5", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libsvn-doc", ver: "1.6.12dfsg-5", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libsvn-java", ver: "1.6.12dfsg-5", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libsvn-perl", ver: "1.6.12dfsg-5", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libsvn-ruby", ver: "1.6.12dfsg-5", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libsvn-ruby1.8", ver: "1.6.12dfsg-5", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libsvn1", ver: "1.6.12dfsg-5", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "python-subversion", ver: "1.6.12dfsg-5", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "subversion", ver: "1.6.12dfsg-5", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "subversion-tools", ver: "1.6.12dfsg-5", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libapache2-svn", ver: "1.6.16dfsg-1", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libsvn-dev", ver: "1.6.16dfsg-1", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libsvn-doc", ver: "1.6.16dfsg-1", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libsvn-java", ver: "1.6.16dfsg-1", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libsvn-perl", ver: "1.6.16dfsg-1", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libsvn-ruby", ver: "1.6.16dfsg-1", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libsvn-ruby1.8", ver: "1.6.16dfsg-1", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libsvn1", ver: "1.6.16dfsg-1", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "python-subversion", ver: "1.6.16dfsg-1", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "subversion", ver: "1.6.16dfsg-1", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "subversion-tools", ver: "1.6.16dfsg-1", rls: "DEB7" ) ) != NULL){
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

