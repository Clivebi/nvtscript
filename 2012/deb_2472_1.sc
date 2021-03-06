if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.71350" );
	script_tag( name: "cvss_base", value: "9.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:S/C:C/I:C/A:C" );
	script_cve_id( "CVE-2012-0208" );
	script_version( "$Revision: 14275 $" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-18 15:39:45 +0100 (Mon, 18 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2012-05-31 11:44:54 -0400 (Thu, 31 May 2012)" );
	script_name( "Debian Security Advisory DSA 2472-1 (gridengine)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2012 E-Soft Inc. http://www.securityspace.com" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB6" );
	script_xref( name: "URL", value: "https://secure1.securityspace.com/smysecure/catid.html?in=DSA%202472-1" );
	script_tag( name: "insight", value: "Dave Love discovered that users who are allowed to submit jobs to a
Grid Engine installation can escalate their privileges to root because
the environment is not properly sanitized before creating processes.

For the stable distribution (squeeze), this problem has been fixed in
version 6.2u5-1squeeze1.

For the unstable distribution (sid), this problem has been fixed in
version 6.2u5-6." );
	script_tag( name: "solution", value: "We recommend that you upgrade your gridengine packages." );
	script_tag( name: "summary", value: "The remote host is missing an update to gridengine
announced via advisory DSA 2472-1." );
	script_tag( name: "qod_type", value: "package" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(( res = isdpkgvuln( pkg: "gridengine-client", ver: "6.2u5-1squeeze1", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "gridengine-common", ver: "6.2u5-1squeeze1", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "gridengine-exec", ver: "6.2u5-1squeeze1", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "gridengine-master", ver: "6.2u5-1squeeze1", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "gridengine-qmon", ver: "6.2u5-1squeeze1", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libdrmaa-dev", ver: "6.2u5-1squeeze1", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libdrmaa-java", ver: "6.2u5-1squeeze1", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libdrmaa1.0", ver: "6.2u5-1squeeze1", rls: "DEB6" ) ) != NULL){
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

