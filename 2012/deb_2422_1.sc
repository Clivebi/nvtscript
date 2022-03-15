if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.71150" );
	script_cve_id( "CVE-2012-1571" );
	script_version( "$Revision: 14275 $" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-18 15:39:45 +0100 (Mon, 18 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2012-03-12 11:33:02 -0400 (Mon, 12 Mar 2012)" );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:N/A:P" );
	script_name( "Debian Security Advisory DSA 2422-1 (file)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2012 E-Soft Inc. http://www.securityspace.com" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB6" );
	script_xref( name: "URL", value: "https://secure1.securityspace.com/smysecure/catid.html?in=DSA%202422-1" );
	script_tag( name: "insight", value: "The file type identification tool, file, and its associated library,
libmagic, do not properly process malformed files in the Composite
Document File (CDF) format, leading to crashes.

Note that after this update, file may return different detection
results for CDF files (well-formed or not).  The new detections are
believed to be more accurate.

For the stable distribution (squeeze), this problem has been fixed in
version 5.04-5+squeeze1." );
	script_tag( name: "solution", value: "We recommend that you upgrade your file packages." );
	script_tag( name: "summary", value: "The remote host is missing an update to file
announced via advisory DSA 2422-1." );
	script_tag( name: "qod_type", value: "package" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(( res = isdpkgvuln( pkg: "file", ver: "5.04-5+squeeze1", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libmagic-dev", ver: "5.04-5+squeeze1", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libmagic1", ver: "5.04-5+squeeze1", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "python-magic", ver: "5.04-5+squeeze1", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "python-magic-dbg", ver: "5.04-5+squeeze1", rls: "DEB6" ) ) != NULL){
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

