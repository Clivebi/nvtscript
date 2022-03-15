if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.70572" );
	script_cve_id( "CVE-2011-4358" );
	script_tag( name: "cvss_base", value: "6.4" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:N" );
	script_version( "$Revision: 14275 $" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-18 15:39:45 +0100 (Mon, 18 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2012-02-11 02:33:52 -0500 (Sat, 11 Feb 2012)" );
	script_name( "Debian Security Advisory DSA 2359-1 (mojarra)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2012 E-Soft Inc. http://www.securityspace.com" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB(6|7)" );
	script_xref( name: "URL", value: "https://secure1.securityspace.com/smysecure/catid.html?in=DSA%202359-1" );
	script_tag( name: "insight", value: "It was discovered that Mojarra, an implementation of JavaServer Faces,
evaluates untrusted values as EL expressions if includeViewParameters
is set to true.

For the stable distribution (squeeze), this problem has been fixed in
version 2.0.3-1+squeeze1.

For the testing distribution (wheezy) and the unstable distribution
(sid), this problem has been fixed in version 2.0.3-2." );
	script_tag( name: "solution", value: "We recommend that you upgrade your mojarra packages." );
	script_tag( name: "summary", value: "The remote host is missing an update to mojarra
announced via advisory DSA 2359-1." );
	script_tag( name: "qod_type", value: "package" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(( res = isdpkgvuln( pkg: "libjsf-api-java", ver: "2.0.3-1+squeeze1", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libjsf-impl-java", ver: "2.0.3-1+squeeze1", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libjsf-java-doc", ver: "2.0.3-1+squeeze1", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libjsf-api-java", ver: "2.0.3-2", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libjsf-impl-java", ver: "2.0.3-2", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libjsf-java-doc", ver: "2.0.3-2", rls: "DEB7" ) ) != NULL){
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

