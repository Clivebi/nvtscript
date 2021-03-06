if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.703224" );
	script_version( "$Revision: 14278 $" );
	script_cve_id( "CVE-2013-7439" );
	script_name( "Debian Security Advisory DSA 3224-1 (libx11 - security update)" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-18 15:47:26 +0100 (Mon, 18 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2015-04-12 00:00:00 +0200 (Sun, 12 Apr 2015)" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	script_xref( name: "URL", value: "http://www.debian.org/security/2015/dsa-3224.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2015 Greenbone Networks GmbH http://greenbone.net" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB7" );
	script_tag( name: "affected", value: "libx11 on Debian Linux" );
	script_tag( name: "solution", value: "For the stable distribution (wheezy),
this problem has been fixed in version 2:1.5.0-1+deb7u2.

For the upcoming stable distribution (jessie), this problem has been
fixed in version 2:1.6.0-1.

For the unstable distribution (sid), this problem has been fixed in
version 2:1.6.0-1.

We recommend that you upgrade your libx11 packages." );
	script_tag( name: "summary", value: "Abhishek Arya discovered a
buffer overflow in the MakeBigReq macro provided by libx11, which could result
in denial of service or the execution of arbitrary code.

Several other xorg packages (e.g. libxrender) will be recompiled against
the fixed package after the release of this update." );
	script_tag( name: "vuldetect", value: "This check tests the installed software
version using the apt package manager." );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(( res = isdpkgvuln( pkg: "libx11-6:amd64", ver: "2:1.5.0-1+deb7u2", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libx11-6:i386", ver: "2:1.5.0-1+deb7u2", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libx11-6-dbg:amd64", ver: "2:1.5.0-1+deb7u2", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libx11-6-dbg:i386", ver: "2:1.5.0-1+deb7u2", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libx11-data", ver: "2:1.5.0-1+deb7u2", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libx11-dev:amd64", ver: "2:1.5.0-1+deb7u2", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libx11-dev:i386", ver: "2:1.5.0-1+deb7u2", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libx11-doc", ver: "2:1.5.0-1+deb7u2", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libx11-xcb-dev", ver: "2:1.5.0-1+deb7u2", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libx11-xcb1:amd64", ver: "2:1.5.0-1+deb7u2", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libx11-xcb1:i386", ver: "2:1.5.0-1+deb7u2", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libx11-xcb1-dbg:amd64", ver: "2:1.5.0-1+deb7u2", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libx11-xcb1-dbg:i386", ver: "2:1.5.0-1+deb7u2", rls: "DEB7" ) ) != NULL){
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

