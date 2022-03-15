if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.703491" );
	script_version( "$Revision: 14279 $" );
	script_cve_id( "CVE-2015-7575", "CVE-2016-1523", "CVE-2016-1930", "CVE-2016-1935" );
	script_name( "Debian Security Advisory DSA 3491-1 (icedove - security update)" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-18 15:48:34 +0100 (Mon, 18 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2016-03-08 12:37:42 +0530 (Tue, 08 Mar 2016)" );
	script_tag( name: "cvss_base", value: "10.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:C/A:C" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	script_xref( name: "URL", value: "http://www.debian.org/security/2016/dsa-3491.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2016 Greenbone Networks GmbH http://greenbone.net" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB(9|7|8)" );
	script_tag( name: "affected", value: "icedove on Debian Linux" );
	script_tag( name: "solution", value: "For the oldstable distribution (wheezy), these problems have been fixed
in version 38.6.0-1~deb7u1.

For the stable distribution (jessie), these problems have been fixed in
version 38.6.0-1~deb8u1.

For the testing distribution (stretch), these problems have been fixed
in version 38.6.0-1.

For the unstable distribution (sid), these problems have been fixed in
version 38.6.0-1.

We recommend that you upgrade your icedove packages." );
	script_tag( name: "summary", value: "Multiple security issues have been found in Icedove, Debian's version of
the Mozilla Thunderbird mail client: Multiple memory safety errors,
integer overflows, buffer overflows and other implementation errors may
lead to the execution of arbitrary code or denial of service." );
	script_tag( name: "vuldetect", value: "This check tests the installed software version using the apt package manager." );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(( res = isdpkgvuln( pkg: "calendar-google-provider", ver: "38.6.0-1", rls: "DEB9" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "icedove", ver: "38.6.0-1", rls: "DEB9" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "icedove-dbg", ver: "38.6.0-1", rls: "DEB9" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "icedove-dev", ver: "38.6.0-1", rls: "DEB9" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "iceowl-extension", ver: "38.6.0-1", rls: "DEB9" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "calendar-google-provider", ver: "38.6.0-1~deb7u1", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "icedove", ver: "38.6.0-1~deb7u1", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "icedove-dbg", ver: "38.6.0-1~deb7u1", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "icedove-dev", ver: "38.6.0-1~deb7u1", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "iceowl-extension", ver: "38.6.0-1~deb7u1", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "calendar-google-provider", ver: "38.6.0-1~deb8u1", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "icedove", ver: "38.6.0-1~deb8u1", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "icedove-dbg", ver: "38.6.0-1~deb8u1", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "icedove-dev", ver: "38.6.0-1~deb8u1", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "iceowl-extension", ver: "38.6.0-1~deb8u1", rls: "DEB8" ) ) != NULL){
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

