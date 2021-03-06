if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.702822" );
	script_version( "$Revision: 14276 $" );
	script_cve_id( "CVE-2013-6424" );
	script_name( "Debian Security Advisory DSA 2822-1 (xorg-server - integer underflow)" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-18 15:43:56 +0100 (Mon, 18 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2013-12-18 00:00:00 +0100 (Wed, 18 Dec 2013)" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:P" );
	script_xref( name: "URL", value: "http://www.debian.org/security/2013/dsa-2822.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2013 Greenbone Networks GmbH http://greenbone.net" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB(6|7)" );
	script_tag( name: "affected", value: "xorg-server on Debian Linux" );
	script_tag( name: "solution", value: "For the oldstable distribution (squeeze), this problem has been fixed in
version 1.7.7-18.

For the stable distribution (wheezy), this problem has been fixed in
version 1.12.4-6+deb7u2.

For the unstable distribution (sid), this problem will be fixed soon.

We recommend that you upgrade your xorg-server packages." );
	script_tag( name: "summary", value: "Bryan Quigley discovered an integer underflow in the Xorg X server which
could lead to denial of service or the execution of arbitrary code." );
	script_tag( name: "vuldetect", value: "This check tests the installed software version using the apt package manager." );
	script_tag( name: "qod_type", value: "package" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(( res = isdpkgvuln( pkg: "xdmx", ver: "1.7.7-18", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "xdmx-tools", ver: "1.7.7-18", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "xnest", ver: "1.7.7-18", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "xserver-common", ver: "1.7.7-18", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "xserver-xephyr", ver: "1.7.7-18", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "xserver-xfbdev", ver: "1.7.7-18", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "xserver-xorg-core", ver: "1.7.7-18", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "xserver-xorg-core-dbg", ver: "1.7.7-18", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "xserver-xorg-dev", ver: "1.7.7-18", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "xvfb", ver: "1.7.7-18", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "xdmx", ver: "1.12.4-6+deb7u2", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "xdmx-tools", ver: "1.12.4-6+deb7u2", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "xnest", ver: "1.12.4-6+deb7u2", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "xserver-common", ver: "1.12.4-6+deb7u2", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "xserver-xephyr", ver: "1.12.4-6+deb7u2", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "xserver-xfbdev", ver: "1.12.4-6+deb7u2", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "xserver-xorg-core", ver: "1.12.4-6+deb7u2", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "xserver-xorg-core-dbg", ver: "1.12.4-6+deb7u2", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "xserver-xorg-dev", ver: "1.12.4-6+deb7u2", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "xvfb", ver: "1.12.4-6+deb7u2", rls: "DEB7" ) ) != NULL){
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

