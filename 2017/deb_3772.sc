if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.703772" );
	script_version( "2021-09-14T10:02:44+0000" );
	script_cve_id( "CVE-2016-10164" );
	script_name( "Debian Security Advisory DSA 3772-1 (libxpm - security update)" );
	script_tag( name: "last_modification", value: "2021-09-14 10:02:44 +0000 (Tue, 14 Sep 2021)" );
	script_tag( name: "creation_date", value: "2017-01-26 00:00:00 +0100 (Thu, 26 Jan 2017)" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2018-01-05 02:30:00 +0000 (Fri, 05 Jan 2018)" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	script_xref( name: "URL", value: "http://www.debian.org/security/2017/dsa-3772.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2017 Greenbone Networks GmbH" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB(8|9)" );
	script_tag( name: "affected", value: "libxpm on Debian Linux" );
	script_tag( name: "solution", value: "For the stable distribution (jessie),
this problem has been fixed in version 1:3.5.12-0+deb8u1. This update is based
on a new upstream version of libxpm including additional bug fixes.

For the testing distribution (stretch) and the unstable distribution
(sid), this problem has been fixed in version 1:3.5.12-1.

We recommend that you upgrade your libxpm packages." );
	script_tag( name: "summary", value: "Tobias Stoeckmann discovered that the
libXpm library contained two integer overflow flaws, leading to a heap out-of-bounds
write, while parsing XPM extensions in a file. An attacker can provide a specially
crafted XPM file that, when processed by an application using the libXpm
library, would cause a denial-of-service against the application, or
potentially, the execution of arbitrary code with the privileges of the
user running the application." );
	script_tag( name: "vuldetect", value: "This check tests the installed software
version using the apt package manager." );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(( res = isdpkgvuln( pkg: "libxpm-dev:amd64", ver: "1:3.5.12-0+deb8u1", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libxpm-dev:i386", ver: "1:3.5.12-0+deb8u1", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libxpm4:amd64", ver: "1:3.5.12-0+deb8u1", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libxpm4:amd64", ver: "1:3.5.12-0+deb8u1", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libxpm4-dbg:amd64", ver: "1:3.5.12-0+deb8u1", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libxpm4-dbg:i386", ver: "1:3.5.12-0+deb8u1", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "xpmutils", ver: "1:3.5.12-0+deb8u1", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libxpm-dev:amd64", ver: "1:3.5.12-1", rls: "DEB9" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libxpm-dev:amd64", ver: "1:3.5.12-1", rls: "DEB9" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libxpm-dev:i386", ver: "1:3.5.12-1", rls: "DEB9" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libxpm4:amd64", ver: "1:3.5.12-1", rls: "DEB9" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libxpm4:i386", ver: "1:3.5.12-1", rls: "DEB9" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "xpmutils", ver: "1:3.5.12-1", rls: "DEB9" ) ) != NULL){
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

