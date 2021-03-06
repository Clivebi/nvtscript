if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.703326" );
	script_version( "$Revision: 14278 $" );
	script_cve_id( "CVE-2015-3228" );
	script_name( "Debian Security Advisory DSA 3326-1 (ghostscript - security update)" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-18 15:47:26 +0100 (Mon, 18 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2015-08-02 00:00:00 +0200 (Sun, 02 Aug 2015)" );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	script_xref( name: "URL", value: "http://www.debian.org/security/2015/dsa-3326.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2015 Greenbone Networks GmbH http://greenbone.net" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB7" );
	script_tag( name: "affected", value: "ghostscript on Debian Linux" );
	script_tag( name: "solution", value: "For the oldstable distribution (wheezy),
this problem has been fixed in version 9.05~dfsg-6.3+deb7u2.

For the stable distribution (jessie), this problem has been fixed in
version 9.06~dfsg-2+deb8u1.

For the testing distribution (stretch), this problem has been fixed
in version 9.15~dfsg-1.

For the unstable distribution (sid), this problem has been fixed in
version 9.15~dfsg-1.

We recommend that you upgrade your ghostscript packages." );
	script_tag( name: "summary", value: "William Robinet and Stefan Cornelius
discovered an integer overflow in Ghostscript, the GPL PostScript/PDF interpreter,
which may result in denial of service or potentially execution of arbitrary code
if a specially crafted file is opened." );
	script_tag( name: "vuldetect", value: "This check tests the installed software
version using the apt package manager." );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(( res = isdpkgvuln( pkg: "ghostscript", ver: "9.05~dfsg-6.3+deb7u2", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "ghostscript-cups", ver: "9.05~dfsg-6.3+deb7u2", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "ghostscript-dbg", ver: "9.05~dfsg-6.3+deb7u2", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "ghostscript-doc", ver: "9.05~dfsg-6.3+deb7u2", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "ghostscript-x", ver: "9.05~dfsg-6.3+deb7u2", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libgs-dev", ver: "9.05~dfsg-6.3+deb7u2", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libgs9", ver: "9.05~dfsg-6.3+deb7u2", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libgs9-common", ver: "9.05~dfsg-6.3+deb7u2", rls: "DEB7" ) ) != NULL){
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

