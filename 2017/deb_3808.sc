if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.703808" );
	script_version( "2021-09-15T11:15:39+0000" );
	script_cve_id( "CVE-2017-6498", "CVE-2017-6499", "CVE-2017-6500" );
	script_name( "Debian Security Advisory DSA 3808-1 (imagemagick - security update)" );
	script_tag( name: "last_modification", value: "2021-09-15 11:15:39 +0000 (Wed, 15 Sep 2021)" );
	script_tag( name: "creation_date", value: "2017-03-13 00:00:00 +0100 (Mon, 13 Mar 2017)" );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:N/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-03-13 13:48:00 +0000 (Wed, 13 Mar 2019)" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	script_xref( name: "URL", value: "http://www.debian.org/security/2017/dsa-3808.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2017 Greenbone Networks GmbH" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB(9|8)" );
	script_tag( name: "affected", value: "imagemagick on Debian Linux" );
	script_tag( name: "solution", value: "For the stable distribution (jessie), these problems have been fixed in
version 8:6.8.9.9-5+deb8u8.

For the upcoming stable distribution (stretch), these problems have been
fixed in version 8:6.9.7.4+dfsg-2.

For the unstable distribution (sid), these problems have been fixed in
version 8:6.9.7.4+dfsg-2.

We recommend that you upgrade your imagemagick packages." );
	script_tag( name: "summary", value: "This update fixes several vulnerabilities in imagemagick: Various memory
handling problems and cases of missing or incomplete input sanitising
may result in denial of service or the execution of arbitrary code if
malformed TGA, Sun or PSD files are processed.

This update also fixes visual artefacts when running -sharpen on CMYK
images (no security impact, but piggybacked on top of the security
update with approval of the Debian stable release managers since it's
a regression in jessie compared to wheezy)." );
	script_tag( name: "vuldetect", value: "This check tests the installed software version using the apt package manager." );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(( res = isdpkgvuln( pkg: "imagemagick", ver: "8:6.9.7.4+dfsg-2", rls: "DEB9" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "imagemagick-6-common", ver: "8:6.9.7.4+dfsg-2", rls: "DEB9" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "imagemagick-6-doc", ver: "8:6.9.7.4+dfsg-2", rls: "DEB9" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "imagemagick-6.q16", ver: "8:6.9.7.4+dfsg-2", rls: "DEB9" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "imagemagick-6.q16hdri", ver: "8:6.9.7.4+dfsg-2", rls: "DEB9" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "imagemagick-common", ver: "8:6.9.7.4+dfsg-2", rls: "DEB9" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "imagemagick-doc", ver: "8:6.9.7.4+dfsg-2", rls: "DEB9" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libimage-magick-perl", ver: "8:6.9.7.4+dfsg-2", rls: "DEB9" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libimage-magick-q16-perl", ver: "8:6.9.7.4+dfsg-2", rls: "DEB9" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libimage-magick-q16hdri-perl", ver: "8:6.9.7.4+dfsg-2", rls: "DEB9" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libmagick++-6-headers", ver: "8:6.9.7.4+dfsg-2", rls: "DEB9" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libmagick++-6.q16-7", ver: "8:6.9.7.4+dfsg-2", rls: "DEB9" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libmagick++-6.q16-dev", ver: "8:6.9.7.4+dfsg-2", rls: "DEB9" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libmagick++-6.q16hdri-7", ver: "8:6.9.7.4+dfsg-2", rls: "DEB9" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libmagick++-6.q16hdri-dev", ver: "8:6.9.7.4+dfsg-2", rls: "DEB9" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libmagick++-dev", ver: "8:6.9.7.4+dfsg-2", rls: "DEB9" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libmagickcore-6-arch-config", ver: "8:6.9.7.4+dfsg-2", rls: "DEB9" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libmagickcore-6-headers", ver: "8:6.9.7.4+dfsg-2", rls: "DEB9" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libmagickcore-6.q16-3", ver: "8:6.9.7.4+dfsg-2", rls: "DEB9" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libmagickcore-6.q16-3-extra", ver: "8:6.9.7.4+dfsg-2", rls: "DEB9" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libmagickcore-6.q16-dev", ver: "8:6.9.7.4+dfsg-2", rls: "DEB9" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libmagickcore-6.q16hdri-3", ver: "8:6.9.7.4+dfsg-2", rls: "DEB9" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libmagickcore-6.q16hdri-3-extra", ver: "8:6.9.7.4+dfsg-2", rls: "DEB9" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libmagickcore-6.q16hdri-dev", ver: "8:6.9.7.4+dfsg-2", rls: "DEB9" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libmagickcore-dev", ver: "8:6.9.7.4+dfsg-2", rls: "DEB9" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libmagickwand-6-headers", ver: "8:6.9.7.4+dfsg-2", rls: "DEB9" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libmagickwand-6.q16-3", ver: "8:6.9.7.4+dfsg-2", rls: "DEB9" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libmagickwand-6.q16-dev", ver: "8:6.9.7.4+dfsg-2", rls: "DEB9" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libmagickwand-6.q16hdri-3", ver: "8:6.9.7.4+dfsg-2", rls: "DEB9" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libmagickwand-6.q16hdri-dev", ver: "8:6.9.7.4+dfsg-2", rls: "DEB9" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libmagickwand-dev", ver: "8:6.9.7.4+dfsg-2", rls: "DEB9" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "perlmagick", ver: "8:6.9.7.4+dfsg-2", rls: "DEB9" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "imagemagick", ver: "8:6.8.9.9-5+deb8u8", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "imagemagick-6.q16", ver: "8:6.8.9.9-5+deb8u8", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "imagemagick-common", ver: "8:6.8.9.9-5+deb8u8", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "imagemagick-dbg", ver: "8:6.8.9.9-5+deb8u8", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "imagemagick-doc", ver: "8:6.8.9.9-5+deb8u8", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libimage-magick-perl", ver: "8:6.8.9.9-5+deb8u8", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libimage-magick-q16-perl", ver: "8:6.8.9.9-5+deb8u8", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libmagick++-6-headers", ver: "8:6.8.9.9-5+deb8u8", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libmagick++-6.q16-5", ver: "8:6.8.9.9-5+deb8u8", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libmagick++-6.q16-dev", ver: "8:6.8.9.9-5+deb8u8", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libmagick++-dev", ver: "8:6.8.9.9-5+deb8u8", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libmagickcore-6-arch-config", ver: "8:6.8.9.9-5+deb8u8", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libmagickcore-6-headers", ver: "8:6.8.9.9-5+deb8u8", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libmagickcore-6.q16-2", ver: "8:6.8.9.9-5+deb8u8", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libmagickcore-6.q16-2-extra", ver: "8:6.8.9.9-5+deb8u8", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libmagickcore-6.q16-dev", ver: "8:6.8.9.9-5+deb8u8", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libmagickcore-dev", ver: "8:6.8.9.9-5+deb8u8", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libmagickwand-6-headers", ver: "8:6.8.9.9-5+deb8u8", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libmagickwand-6.q16-2", ver: "8:6.8.9.9-5+deb8u8", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libmagickwand-6.q16-dev", ver: "8:6.8.9.9-5+deb8u8", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libmagickwand-dev", ver: "8:6.8.9.9-5+deb8u8", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "perlmagick", ver: "8:6.8.9.9-5+deb8u8", rls: "DEB8" ) ) != NULL){
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

