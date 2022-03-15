if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.68991" );
	script_version( "$Revision: 14275 $" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-18 15:39:45 +0100 (Mon, 18 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2011-03-07 16:04:02 +0100 (Mon, 07 Mar 2011)" );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_cve_id( "CVE-2010-3814", "CVE-2010-3855" );
	script_name( "Debian Security Advisory DSA 2155-1 (freetype)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2011 E-Soft Inc. http://www.securityspace.com" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB(5|6)" );
	script_xref( name: "URL", value: "https://secure1.securityspace.com/smysecure/catid.html?in=DSA%202155-1" );
	script_tag( name: "insight", value: "Two buffer overflows were found in the Freetype font library, which could
lead to the execution of arbitrary code.

For the stable distribution (lenny), this problem has been fixed in
version 2.3.7-2+lenny5.

For the testing distribution (squeeze), this problem has been fixed in
version 2.4.2-2.1.

For the unstable distribution (sid), this problem has been fixed in
version 2.4.2-2.1." );
	script_tag( name: "solution", value: "We recommend that you upgrade your freetype packages." );
	script_tag( name: "summary", value: "The remote host is missing an update to freetype
announced via advisory DSA 2155-1." );
	script_tag( name: "qod_type", value: "package" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(( res = isdpkgvuln( pkg: "freetype2-demos", ver: "2.3.7-2+lenny5", rls: "DEB5" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libfreetype6", ver: "2.3.7-2+lenny5", rls: "DEB5" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libfreetype6-dev", ver: "2.3.7-2+lenny5", rls: "DEB5" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libfreetype6-udeb", ver: "2.3.7-2+lenny5", rls: "DEB5" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "freetype2-demos", ver: "2.4.2-2.1", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libfreetype6", ver: "2.4.2-2.1", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libfreetype6-dev", ver: "2.4.2-2.1", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libfreetype6-udeb", ver: "2.4.2-2.1", rls: "DEB6" ) ) != NULL){
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

