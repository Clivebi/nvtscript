if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.703438" );
	script_version( "$Revision: 14279 $" );
	script_cve_id( "CVE-2015-8025" );
	script_name( "Debian Security Advisory DSA 3438-1 (xscreensaver - security update)" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-18 15:48:34 +0100 (Mon, 18 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2016-01-09 00:00:00 +0100 (Sat, 09 Jan 2016)" );
	script_tag( name: "cvss_base", value: "2.1" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:L/Au:N/C:N/I:P/A:N" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	script_xref( name: "URL", value: "http://www.debian.org/security/2016/dsa-3438.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2016 Greenbone Networks GmbH http://greenbone.net" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB(9|8|7)" );
	script_tag( name: "affected", value: "xscreensaver on Debian Linux" );
	script_tag( name: "solution", value: "For the oldstable distribution (wheezy),
this problem has been fixed in version 5.15-3+deb7u1.

For the stable distribution (jessie), this problem has been fixed in
version 5.30-1+deb8u1.

For the testing (stretch) and unstable (sid) distributions, this problem
has been fixed in version 5.34-1.

We recommend that you upgrade your xscreensaver packages." );
	script_tag( name: "summary", value: "It was discovered that unplugging one of
the monitors in a multi-monitor setup can cause xscreensaver to crash. Someone with
physical access to a machine could use this problem to bypass a locked session." );
	script_tag( name: "vuldetect", value: "This check tests the installed software
version using the apt package manager." );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(( res = isdpkgvuln( pkg: "xscreensaver", ver: "5.34-1", rls: "DEB9" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "xscreensaver-data", ver: "5.34-1", rls: "DEB9" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "xscreensaver-data-extra", ver: "5.34-1", rls: "DEB9" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "xscreensaver-gl", ver: "5.34-1", rls: "DEB9" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "xscreensaver-gl-extra", ver: "5.34-1", rls: "DEB9" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "xscreensaver-screensaver-bsod", ver: "5.34-1", rls: "DEB9" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "xscreensaver-screensaver-webcollage", ver: "5.34-1", rls: "DEB9" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "xscreensaver", ver: "5.30-1+deb8u1", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "xscreensaver-data", ver: "5.30-1+deb8u1", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "xscreensaver-data-extra", ver: "5.30-1+deb8u1", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "xscreensaver-gl", ver: "5.30-1+deb8u1", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "xscreensaver-gl-extra", ver: "5.30-1+deb8u1", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "xscreensaver-screensaver-bsod", ver: "5.30-1+deb8u1", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "xscreensaver-screensaver-webcollage", ver: "5.30-1+deb8u1", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "xscreensaver", ver: "5.15-3+deb7u1", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "xscreensaver-data", ver: "5.15-3+deb7u1", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "xscreensaver-data-extra", ver: "5.15-3+deb7u1", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "xscreensaver-gl", ver: "5.15-3+deb7u1", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "xscreensaver-gl-extra", ver: "5.15-3+deb7u1", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "xscreensaver-screensaver-bsod", ver: "5.15-3+deb7u1", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "xscreensaver-screensaver-webcollage", ver: "5.15-3+deb7u1", rls: "DEB7" ) ) != NULL){
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

