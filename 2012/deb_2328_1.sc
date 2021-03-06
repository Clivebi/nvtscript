if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.70543" );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:P/A:N" );
	script_cve_id( "CVE-2011-3256" );
	script_version( "$Revision: 14275 $" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-18 15:39:45 +0100 (Mon, 18 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2012-02-11 02:26:31 -0500 (Sat, 11 Feb 2012)" );
	script_name( "Debian Security Advisory DSA 2328-1 (freetype)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2012 E-Soft Inc. http://www.securityspace.com" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB(5|6)" );
	script_xref( name: "URL", value: "https://secure1.securityspace.com/smysecure/catid.html?in=DSA%202328-1" );
	script_tag( name: "insight", value: "It was discovered that missing input sanitising in Freetype's glyph
handling could lead to memory corruption, resulting in denial of service
or the execution of arbitrary code.

For the oldstable distribution (lenny), this problem has been fixed in
version 2.3.7-2+lenny7.

For the stable distribution (squeeze), this problem has been fixed in
version 2.4.2-2.1+squeeze2.

For the unstable distribution (sid), this problem has been fixed in
version 2.4.7-1." );
	script_tag( name: "solution", value: "We recommend that you upgrade your freetype packages." );
	script_tag( name: "summary", value: "The remote host is missing an update to freetype
announced via advisory DSA 2328-1." );
	script_tag( name: "qod_type", value: "package" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(( res = isdpkgvuln( pkg: "freetype2-demos", ver: "2.3.7-2+lenny7", rls: "DEB5" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libfreetype6", ver: "2.3.7-2+lenny7", rls: "DEB5" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libfreetype6-dev", ver: "2.3.7-2+lenny7", rls: "DEB5" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libfreetype6-udeb", ver: "2.3.7-2+lenny6", rls: "DEB5" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "freetype2-demos", ver: "2.4.2-2.1+squeeze2", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libfreetype6", ver: "2.4.2-2.1+squeeze2", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libfreetype6-dev", ver: "2.4.2-2.1+squeeze2", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libfreetype6-udeb", ver: "2.4.2-2.1+squeeze2", rls: "DEB6" ) ) != NULL){
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

