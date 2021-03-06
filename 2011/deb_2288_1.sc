if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.70061" );
	script_version( "$Revision: 14275 $" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-18 15:39:45 +0100 (Mon, 18 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2011-08-07 17:37:07 +0200 (Sun, 07 Aug 2011)" );
	script_cve_id( "CVE-2011-2696" );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_name( "Debian Security Advisory DSA 2288-1 (libsndfile)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2011 E-Soft Inc. http://www.securityspace.com" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB(5|6)" );
	script_xref( name: "URL", value: "https://secure1.securityspace.com/smysecure/catid.html?in=DSA%202288-1" );
	script_tag( name: "insight", value: "Hossein Lotfi discovered an integer overflow in libsndfile's code to
parse Paris Audio files, which could potentially lead to the execution
of arbitrary code.

For the oldstable distribution (lenny), this problem has been fixed in
version 1.0.17-4+lenny3.

For the stable distribution (squeeze), this problem has been fixed in
version 1.0.21-3+squeeze1

For the unstable distribution (sid), this problem has been fixed in
version 1.0.25-1." );
	script_tag( name: "solution", value: "We recommend that you upgrade your libsndfile packages." );
	script_tag( name: "summary", value: "The remote host is missing an update to libsndfile
announced via advisory DSA 2288-1." );
	script_tag( name: "qod_type", value: "package" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(( res = isdpkgvuln( pkg: "libsndfile1", ver: "1.0.17-4+lenny3", rls: "DEB5" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libsndfile1-dev", ver: "1.0.17-4+lenny3", rls: "DEB5" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "sndfile-programs", ver: "1.0.17-4+lenny3", rls: "DEB5" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libsndfile1", ver: "1.0.21-3+squeeze1", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libsndfile1-dev", ver: "1.0.21-3+squeeze1", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "sndfile-programs", ver: "1.0.21-3+squeeze1", rls: "DEB6" ) ) != NULL){
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

