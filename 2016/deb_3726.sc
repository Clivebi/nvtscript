if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.703726" );
	script_version( "2021-09-20T13:38:59+0000" );
	script_cve_id( "CVE-2016-7799", "CVE-2016-7906", "CVE-2016-8677", "CVE-2016-8862", "CVE-2016-9556", "CVE-2016-9559" );
	script_name( "Debian Security Advisory DSA 3726-1 (imagemagick - security update)" );
	script_tag( name: "last_modification", value: "2021-09-20 13:38:59 +0000 (Mon, 20 Sep 2021)" );
	script_tag( name: "creation_date", value: "2016-11-26 00:00:00 +0100 (Sat, 26 Nov 2016)" );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	script_xref( name: "URL", value: "http://www.debian.org/security/2016/dsa-3726.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2016 Greenbone Networks GmbH" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB8" );
	script_tag( name: "affected", value: "imagemagick on Debian Linux" );
	script_tag( name: "solution", value: "For the stable distribution (jessie),
these problems have been fixed in version 8:6.8.9.9-5+deb8u6.

For the unstable distribution (sid), these problems have been fixed in
version 8:6.9.6.5+dfsg-1.

We recommend that you upgrade your imagemagick packages." );
	script_tag( name: "summary", value: "Several issues have been discovered
in ImageMagick, a popular set of programs and libraries for image manipulation.
These issues include several problems in memory handling that can result in a
denial of service attack or in execution of arbitrary code by an attacker with
control on the image input." );
	script_tag( name: "vuldetect", value: "This check tests the installed
software version using the apt package manager." );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(( res = isdpkgvuln( pkg: "imagemagick", ver: "8:6.8.9.9-5+deb8u6", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "imagemagick-6.q16", ver: "8:6.8.9.9-5+deb8u6", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "imagemagick-common", ver: "8:6.8.9.9-5+deb8u6", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "imagemagick-dbg:amd64", ver: "8:6.8.9.9-5+deb8u6", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "imagemagick-dbg:i386", ver: "8:6.8.9.9-5+deb8u6", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "imagemagick-doc", ver: "8:6.8.9.9-5+deb8u6", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libimage-magick-perl", ver: "8:6.8.9.9-5+deb8u6", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libimage-magick-q16-perl", ver: "8:6.8.9.9-5+deb8u6", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libmagick++-6-headers", ver: "8:6.8.9.9-5+deb8u6", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libmagick++-6.q16-5:amd64", ver: "8:6.8.9.9-5+deb8u6", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libmagick++-6.q16-5:i386", ver: "8:6.8.9.9-5+deb8u6", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libmagick++-6.q16-dev:amd64", ver: "8:6.8.9.9-5+deb8u6", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libmagick++-6.q16-dev:i386", ver: "8:6.8.9.9-5+deb8u6", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libmagick++-dev", ver: "8:6.8.9.9-5+deb8u6", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libmagickcore-6-arch-config:amd64", ver: "8:6.8.9.9-5+deb8u6", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libmagickcore-6-arch-config:i386", ver: "8:6.8.9.9-5+deb8u6", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libmagickcore-6-headers", ver: "8:6.8.9.9-5+deb8u6", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libmagickcore-6.q16-2:amd64", ver: "8:6.8.9.9-5+deb8u6", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libmagickcore-6.q16-2:i386", ver: "8:6.8.9.9-5+deb8u6", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libmagickcore-6.q16-2-extra:amd64", ver: "8:6.8.9.9-5+deb8u6", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libmagickcore-6.q16-2-extra:i386", ver: "8:6.8.9.9-5+deb8u6", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libmagickcore-6.q16-dev:amd64", ver: "8:6.8.9.9-5+deb8u6", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libmagickcore-6.q16-dev:i386", ver: "8:6.8.9.9-5+deb8u6", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libmagickcore-dev", ver: "8:6.8.9.9-5+deb8u6", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libmagickwand-6-headers", ver: "8:6.8.9.9-5+deb8u6", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libmagickwand-6.q16-2:amd64", ver: "8:6.8.9.9-5+deb8u6", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libmagickwand-6.q16-2:i386", ver: "8:6.8.9.9-5+deb8u6", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libmagickwand-6.q16-dev:amd64", ver: "8:6.8.9.9-5+deb8u6", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libmagickwand-6.q16-dev:i386", ver: "8:6.8.9.9-5+deb8u6", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libmagickwand-dev", ver: "8:6.8.9.9-5+deb8u6", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "perlmagick", ver: "8:6.8.9.9-5+deb8u6", rls: "DEB8" ) ) != NULL){
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

