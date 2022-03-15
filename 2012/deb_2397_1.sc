if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.70714" );
	script_cve_id( "CVE-2011-4599" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_version( "$Revision: 14275 $" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-18 15:39:45 +0100 (Mon, 18 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2012-02-12 06:35:00 -0500 (Sun, 12 Feb 2012)" );
	script_name( "Debian Security Advisory DSA 2397-1 (icu)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2012 E-Soft Inc. http://www.securityspace.com" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB(5|6)" );
	script_xref( name: "URL", value: "https://secure1.securityspace.com/smysecure/catid.html?in=DSA%202397-1" );
	script_tag( name: "insight", value: "It was discovered that a buffer overflow in the Unicode libraray ICU
could lead to the execution of arbitrary code.

For the oldstable distribution (lenny), this problem has been fixed in
version 3.8.1-3+lenny3.

For the stable distribution (squeeze), this problem has been fixed in
version 4.4.1-8.

For the unstable distribution (sid), this problem has been fixed in
version 4.8.1.1-3." );
	script_tag( name: "solution", value: "We recommend that you upgrade your icu packages." );
	script_tag( name: "summary", value: "The remote host is missing an update to icu
announced via advisory DSA 2397-1." );
	script_tag( name: "qod_type", value: "package" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(( res = isdpkgvuln( pkg: "icu-doc", ver: "3.8.1-3+lenny3", rls: "DEB5" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "lib32icu-dev", ver: "3.8.1-3+lenny3", rls: "DEB5" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "lib32icu38", ver: "3.8.1-3+lenny3", rls: "DEB5" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libicu-dev", ver: "3.8.1-3+lenny3", rls: "DEB5" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libicu38", ver: "3.8.1-3+lenny3", rls: "DEB5" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libicu38-dbg", ver: "3.8.1-3+lenny3", rls: "DEB5" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "icu-doc", ver: "4.4.1-8", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "lib32icu-dev", ver: "4.4.1-8", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "lib32icu44", ver: "4.4.1-8", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libicu-dev", ver: "4.4.1-8", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libicu44", ver: "4.4.1-8", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libicu44-dbg", ver: "4.4.1-8", rls: "DEB6" ) ) != NULL){
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

