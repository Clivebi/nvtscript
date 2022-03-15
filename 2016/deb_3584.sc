if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.703584" );
	script_version( "$Revision: 14275 $" );
	script_cve_id( "CVE-2015-7558", "CVE-2016-4348" );
	script_name( "Debian Security Advisory DSA 3584-1 (librsvg - security update)" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-18 15:39:45 +0100 (Mon, 18 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2016-05-19 00:00:00 +0200 (Thu, 19 May 2016)" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:P" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	script_xref( name: "URL", value: "http://www.debian.org/security/2016/dsa-3584.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2016 Greenbone Networks GmbH http://greenbone.net" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB(8|9)" );
	script_tag( name: "affected", value: "librsvg on Debian Linux" );
	script_tag( name: "solution", value: "For the stable distribution (jessie),
these problems have been fixed in version 2.40.5-1+deb8u2.

For the testing distribution (stretch), these problems have been fixed
in version 2.40.12-1.

For the unstable distribution (sid), these problems have been fixed in
version 2.40.12-1.

We recommend that you upgrade your librsvg packages." );
	script_tag( name: "summary", value: "Gustavo Grieco discovered several flaws
in the way librsvg, a SAX-based renderer library for SVG files, parses SVG files
with circular definitions. A remote attacker can take advantage of these flaws to
cause an application using the librsvg library to crash." );
	script_tag( name: "vuldetect", value: "This check tests the installed software
version using the apt package manager." );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(( res = isdpkgvuln( pkg: "gir1.2-rsvg-2.0:amd64", ver: "2.40.5-1+deb8u2", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "gir1.2-rsvg-2.0:i386", ver: "2.40.5-1+deb8u2", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "librsvg2-2:amd64", ver: "2.40.5-1+deb8u2", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "librsvg2-2:i386", ver: "2.40.5-1+deb8u2", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "librsvg2-bin", ver: "2.40.5-1+deb8u2", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "librsvg2-common:amd64", ver: "2.40.5-1+deb8u2", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "librsvg2-common:i386", ver: "2.40.5-1+deb8u2", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "librsvg2-dbg", ver: "2.40.5-1+deb8u2", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "librsvg2-dev:amd64", ver: "2.40.5-1+deb8u2", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "librsvg2-dev:i386", ver: "2.40.5-1+deb8u2", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "librsvg2-doc", ver: "2.40.5-1+deb8u2", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "gir1.2-rsvg-2.0:amd64", ver: "2.40.12-1", rls: "DEB9" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "gir1.2-rsvg-2.0:i386", ver: "2.40.12-1", rls: "DEB9" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "librsvg2-2:amd64", ver: "2.40.12-1", rls: "DEB9" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "librsvg2-2:i386", ver: "2.40.12-1", rls: "DEB9" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "librsvg2-bin", ver: "2.40.12-1", rls: "DEB9" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "librsvg2-common:amd64", ver: "2.40.12-1", rls: "DEB9" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "librsvg2-common:i386", ver: "2.40.12-1", rls: "DEB9" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "librsvg2-dev:amd64", ver: "2.40.12-1", rls: "DEB9" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "librsvg2-dev:i386", ver: "2.40.12-1", rls: "DEB9" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "librsvg2-doc", ver: "2.40.12-1", rls: "DEB9" ) ) != NULL){
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

