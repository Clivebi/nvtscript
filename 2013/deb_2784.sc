if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.702784" );
	script_version( "2020-10-05T06:02:24+0000" );
	script_cve_id( "CVE-2013-4396" );
	script_name( "Debian Security Advisory DSA 2784-1 (xorg-server - use-after-free)" );
	script_tag( name: "last_modification", value: "2020-10-05 06:02:24 +0000 (Mon, 05 Oct 2020)" );
	script_tag( name: "creation_date", value: "2013-10-22 00:00:00 +0200 (Tue, 22 Oct 2013)" );
	script_tag( name: "cvss_base", value: "6.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:S/C:P/I:P/A:P" );
	script_xref( name: "URL", value: "http://www.debian.org/security/2013/dsa-2784.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2013 Greenbone Networks GmbH http://greenbone.net" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB(6|7)" );
	script_tag( name: "affected", value: "xorg-server on Debian Linux" );
	script_tag( name: "solution", value: "For the oldstable distribution (squeeze), this problem has been fixed in
version 1.7.7-17.

For the stable distribution (wheezy), this problem has been fixed in
version 1.12.4-6+deb7u1.

For the testing distribution (jessie), this problem has been fixed in
version 1.14.3-4.

For the unstable distribution (sid), this problem has been fixed in
version 1.14.3-4.

We recommend that you upgrade your xorg-server packages." );
	script_tag( name: "summary", value: "Pedro Ribeiro discovered a use-after-free in the handling of ImageText
requests in the Xorg Xserver, which could result in denial of service
or privilege escalation." );
	script_tag( name: "vuldetect", value: "This check tests the installed software version using the apt package manager." );
	script_tag( name: "qod_type", value: "package" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(( res = isdpkgvuln( pkg: "xdmx", ver: "1.7.7-17", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "xdmx-tools", ver: "1.7.7-17", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "xnest", ver: "1.7.7-17", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "xserver-common", ver: "1.7.7-17", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "xserver-xephyr", ver: "1.7.7-17", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "xserver-xfbdev", ver: "1.7.7-17", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "xserver-xorg-core", ver: "1.7.7-17", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "xserver-xorg-core-dbg", ver: "1.7.7-17", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "xserver-xorg-dev", ver: "1.7.7-17", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "xvfb", ver: "1.7.7-17", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "xdmx", ver: "1.12.4-6+deb7u1", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "xdmx-tools", ver: "1.12.4-6+deb7u1", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "xnest", ver: "1.12.4-6+deb7u1", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "xserver-common", ver: "1.12.4-6+deb7u1", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "xserver-xephyr", ver: "1.12.4-6+deb7u1", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "xserver-xfbdev", ver: "1.12.4-6+deb7u1", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "xserver-xorg-core", ver: "1.12.4-6+deb7u1", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "xserver-xorg-core-dbg", ver: "1.12.4-6+deb7u1", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "xserver-xorg-dev", ver: "1.12.4-6+deb7u1", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "xvfb", ver: "1.12.4-6+deb7u1", rls: "DEB7" ) ) != NULL){
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

