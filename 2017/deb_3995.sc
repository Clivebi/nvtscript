if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.703995" );
	script_version( "2021-09-15T11:15:39+0000" );
	script_cve_id( "CVE-2017-13720", "CVE-2017-13722" );
	script_name( "Debian Security Advisory DSA 3995-1 (libxfont - security update)" );
	script_tag( name: "last_modification", value: "2021-09-15 11:15:39 +0000 (Wed, 15 Sep 2021)" );
	script_tag( name: "creation_date", value: "2017-10-10 00:00:00 +0200 (Tue, 10 Oct 2017)" );
	script_tag( name: "cvss_base", value: "3.6" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:L/Au:N/C:P/I:N/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2017-11-13 02:29:00 +0000 (Mon, 13 Nov 2017)" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	script_xref( name: "URL", value: "http://www.debian.org/security/2017/dsa-3995.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2017 Greenbone Networks GmbH" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB(8|9)" );
	script_tag( name: "affected", value: "libxfont on Debian Linux" );
	script_tag( name: "solution", value: "For the oldstable distribution (jessie), these problems have been fixed
in version 1:1.5.1-1+deb8u1.

For the stable distribution (stretch), these problems have been fixed in
version 1:2.0.1-3+deb9u1.

We recommend that you upgrade your libxfont packages." );
	script_tag( name: "summary", value: "Two vulnerabilities were found in libXfont, the X11 font rasterisation
library, which could result in denial of service or memory disclosure." );
	script_tag( name: "vuldetect", value: "This check tests the installed software version using the apt package manager." );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(( res = isdpkgvuln( pkg: "libxfont-dev", ver: "1:1.5.1-1+deb8u1", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libxfont1", ver: "1:1.5.1-1+deb8u1", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libxfont1-dbg", ver: "1:1.5.1-1+deb8u1", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libxfont-dev", ver: "1:2.0.1-3+deb9u1", rls: "DEB9" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libxfont2", ver: "1:2.0.1-3+deb9u1", rls: "DEB9" ) ) != NULL){
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

