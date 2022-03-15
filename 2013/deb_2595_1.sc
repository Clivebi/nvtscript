if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.702595" );
	script_version( "2020-10-05T06:02:24+0000" );
	script_cve_id( "CVE-2012-4405" );
	script_name( "Debian Security Advisory DSA 2595-1 (ghostscript - integer overflow)" );
	script_tag( name: "last_modification", value: "2020-10-05 06:02:24 +0000 (Mon, 05 Oct 2020)" );
	script_tag( name: "creation_date", value: "2013-09-18 11:53:02 +0200 (Wed, 18 Sep 2013)" );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_xref( name: "URL", value: "http://www.debian.org/security/2012/dsa-2595.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2013 Greenbone Networks GmbH http://greenbone.net" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB(6|7)" );
	script_tag( name: "affected", value: "ghostscript on Debian Linux" );
	script_tag( name: "solution", value: "For the stable distribution (squeeze), this problem has been fixed in
version 8.71~dfsg2-9+squeeze1.

For the testing distribution (wheezy), this problem has been fixed in
version 9.05~dfsg-6.1.

For the unstable distribution (sid), this problem has been fixed in
version 9.05~dfsg-6.1.

We recommend that you upgrade your ghostscript packages." );
	script_tag( name: "summary", value: "Marc Schoenefeld discovered that an integer overflow in the ICC parsing
code of Ghostscript can lead to the execution of arbitrary code." );
	script_tag( name: "vuldetect", value: "This check tests the installed software version using the apt package manager." );
	script_tag( name: "qod_type", value: "package" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(( res = isdpkgvuln( pkg: "ghostscript", ver: "8.71~dfsg2-9+squeeze1", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "ghostscript-cups", ver: "8.71~dfsg2-9+squeeze1", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "ghostscript-doc", ver: "8.71~dfsg2-9+squeeze1", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "ghostscript-x", ver: "8.71~dfsg2-9+squeeze1", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "gs-common", ver: "8.71~dfsg2-9+squeeze1", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "gs-esp", ver: "8.71~dfsg2-9+squeeze1", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "gs-gpl", ver: "8.71~dfsg2-9+squeeze1", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libgs-dev", ver: "8.71~dfsg2-9+squeeze1", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libgs8", ver: "8.71~dfsg2-9+squeeze1", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "ghostscript", ver: "9.05~dfsg-6.1", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "ghostscript-cups", ver: "9.05~dfsg-6.1", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "ghostscript-dbg", ver: "9.05~dfsg-6.1", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "ghostscript-doc", ver: "9.05~dfsg-6.1", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "ghostscript-x", ver: "9.05~dfsg-6.1", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libgs-dev", ver: "9.05~dfsg-6.1", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libgs9", ver: "9.05~dfsg-6.1", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libgs9-common", ver: "9.05~dfsg-6.1", rls: "DEB7" ) ) != NULL){
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

