if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.702838" );
	script_version( "$Revision: 14302 $" );
	script_cve_id( "CVE-2013-6462" );
	script_name( "Debian Security Advisory DSA 2838-1 (libxfont - buffer overflow)" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-19 09:28:48 +0100 (Tue, 19 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2014-01-07 00:00:00 +0100 (Tue, 07 Jan 2014)" );
	script_tag( name: "cvss_base", value: "9.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:C/I:C/A:C" );
	script_xref( name: "URL", value: "http://www.debian.org/security/2014/dsa-2838.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2014 Greenbone Networks GmbH http://greenbone.net" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB(6|7)" );
	script_tag( name: "affected", value: "libxfont on Debian Linux" );
	script_tag( name: "solution", value: "For the oldstable distribution (squeeze), this problem has been fixed in
version 1:1.4.1-4.

For the stable distribution (wheezy), this problem has been fixed in
version 1:1.4.5-3.

For the unstable distribution (sid), this problem has been fixed in
version 1:1.4.7-1.

We recommend that you upgrade your libxfont packages." );
	script_tag( name: "summary", value: "It was discovered that a buffer overflow in the processing of Glyph
Bitmap Distribution fonts (BDF) could result in the execution of
arbitrary code." );
	script_tag( name: "vuldetect", value: "This check tests the installed software version using the apt package manager." );
	script_tag( name: "qod_type", value: "package" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(( res = isdpkgvuln( pkg: "libxfont-dev", ver: "1:1.4.1-4", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libxfont1", ver: "1:1.4.1-4", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libxfont1-dbg", ver: "1:1.4.1-4", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libxfont-dev", ver: "1:1.4.5-3", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libxfont1", ver: "1:1.4.5-3", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libxfont1-dbg", ver: "1:1.4.5-3", rls: "DEB7" ) ) != NULL){
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

