if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.703914" );
	script_version( "2021-09-14T10:02:44+0000" );
	script_cve_id( "CVE-2017-10928", "CVE-2017-11141", "CVE-2017-11170", "CVE-2017-11188", "CVE-2017-11352", "CVE-2017-11360", "CVE-2017-11447", "CVE-2017-11448", "CVE-2017-11449", "CVE-2017-11450", "CVE-2017-9439", "CVE-2017-9440", "CVE-2017-9500", "CVE-2017-9501" );
	script_name( "Debian Security Advisory DSA 3914-1 (imagemagick - security update)" );
	script_tag( name: "last_modification", value: "2021-09-14 10:02:44 +0000 (Tue, 14 Sep 2021)" );
	script_tag( name: "creation_date", value: "2017-07-18 00:00:00 +0200 (Tue, 18 Jul 2017)" );
	script_tag( name: "cvss_base", value: "7.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:C" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-10-03 00:03:00 +0000 (Thu, 03 Oct 2019)" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	script_xref( name: "URL", value: "http://www.debian.org/security/2017/dsa-3914.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2017 Greenbone Networks GmbH" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB(8|9)" );
	script_tag( name: "affected", value: "imagemagick on Debian Linux" );
	script_tag( name: "solution", value: "For the oldstable distribution (jessie), these problems have been fixed
in version 8:6.8.9.9-5+deb8u10.

For the stable distribution (stretch), these problems have been fixed in
version 8:6.9.7.4+dfsg-11+deb9u1.

For the unstable distribution (sid), these problems have been fixed in
version 8:6.9.7.4+dfsg-12.

We recommend that you upgrade your imagemagick packages." );
	script_tag( name: "summary", value: "This updates fixes several vulnerabilities in imagemagick: Various
memory handling problems and cases of missing or incomplete input
sanitising may result in denial of service, memory disclosure or the
execution of arbitrary code if malformed RLE, SVG, PSD, PDB, DPX, MAT,
TGA, VST, CIN, DIB, MPC, EPT, JNG, DJVU, JPEG, ICO, PALM or MNG
files are processed." );
	script_tag( name: "vuldetect", value: "This check tests the installed software version using the apt package manager." );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(( res = isdpkgvuln( pkg: "imagemagick", ver: "8:6.8.9.9-5+deb8u10", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "imagemagick-6.q16", ver: "8:6.8.9.9-5+deb8u10", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "imagemagick-common", ver: "8:6.8.9.9-5+deb8u10", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "imagemagick-dbg", ver: "8:6.8.9.9-5+deb8u10", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "imagemagick-doc", ver: "8:6.8.9.9-5+deb8u10", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libimage-magick-perl", ver: "8:6.8.9.9-5+deb8u10", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libimage-magick-q16-perl", ver: "8:6.8.9.9-5+deb8u10", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libmagick++-6-headers", ver: "8:6.8.9.9-5+deb8u10", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libmagick++-6.q16-5", ver: "8:6.8.9.9-5+deb8u10", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libmagick++-6.q16-dev", ver: "8:6.8.9.9-5+deb8u10", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libmagick++-dev", ver: "8:6.8.9.9-5+deb8u10", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libmagickcore-6-arch-config", ver: "8:6.8.9.9-5+deb8u10", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libmagickcore-6-headers", ver: "8:6.8.9.9-5+deb8u10", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libmagickcore-6.q16-2", ver: "8:6.8.9.9-5+deb8u10", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libmagickcore-6.q16-2-extra", ver: "8:6.8.9.9-5+deb8u10", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libmagickcore-6.q16-dev", ver: "8:6.8.9.9-5+deb8u10", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libmagickcore-dev", ver: "8:6.8.9.9-5+deb8u10", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libmagickwand-6-headers", ver: "8:6.8.9.9-5+deb8u10", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libmagickwand-6.q16-2", ver: "8:6.8.9.9-5+deb8u10", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libmagickwand-6.q16-dev", ver: "8:6.8.9.9-5+deb8u10", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libmagickwand-dev", ver: "8:6.8.9.9-5+deb8u10", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "perlmagick", ver: "8:6.8.9.9-5+deb8u10", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "imagemagick", ver: "8:6.9.7.4+dfsg-11+deb9u1", rls: "DEB9" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "imagemagick-6-common", ver: "8:6.9.7.4+dfsg-11+deb9u1", rls: "DEB9" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "imagemagick-6-doc", ver: "8:6.9.7.4+dfsg-11+deb9u1", rls: "DEB9" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "imagemagick-6.q16", ver: "8:6.9.7.4+dfsg-11+deb9u1", rls: "DEB9" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "imagemagick-6.q16hdri", ver: "8:6.9.7.4+dfsg-11+deb9u1", rls: "DEB9" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "imagemagick-common", ver: "8:6.9.7.4+dfsg-11+deb9u1", rls: "DEB9" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "imagemagick-doc", ver: "8:6.9.7.4+dfsg-11+deb9u1", rls: "DEB9" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libimage-magick-perl", ver: "8:6.9.7.4+dfsg-11+deb9u1", rls: "DEB9" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libimage-magick-q16-perl", ver: "8:6.9.7.4+dfsg-11+deb9u1", rls: "DEB9" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libimage-magick-q16hdri-perl", ver: "8:6.9.7.4+dfsg-11+deb9u1", rls: "DEB9" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libmagick++-6-headers", ver: "8:6.9.7.4+dfsg-11+deb9u1", rls: "DEB9" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libmagick++-6.q16-7", ver: "8:6.9.7.4+dfsg-11+deb9u1", rls: "DEB9" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libmagick++-6.q16-dev", ver: "8:6.9.7.4+dfsg-11+deb9u1", rls: "DEB9" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libmagick++-6.q16hdri-7", ver: "8:6.9.7.4+dfsg-11+deb9u1", rls: "DEB9" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libmagick++-6.q16hdri-dev", ver: "8:6.9.7.4+dfsg-11+deb9u1", rls: "DEB9" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libmagick++-dev", ver: "8:6.9.7.4+dfsg-11+deb9u1", rls: "DEB9" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libmagickcore-6-arch-config", ver: "8:6.9.7.4+dfsg-11+deb9u1", rls: "DEB9" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libmagickcore-6-headers", ver: "8:6.9.7.4+dfsg-11+deb9u1", rls: "DEB9" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libmagickcore-6.q16-3", ver: "8:6.9.7.4+dfsg-11+deb9u1", rls: "DEB9" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libmagickcore-6.q16-3-extra", ver: "8:6.9.7.4+dfsg-11+deb9u1", rls: "DEB9" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libmagickcore-6.q16-dev", ver: "8:6.9.7.4+dfsg-11+deb9u1", rls: "DEB9" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libmagickcore-6.q16hdri-3", ver: "8:6.9.7.4+dfsg-11+deb9u1", rls: "DEB9" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libmagickcore-6.q16hdri-3-extra", ver: "8:6.9.7.4+dfsg-11+deb9u1", rls: "DEB9" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libmagickcore-6.q16hdri-dev", ver: "8:6.9.7.4+dfsg-11+deb9u1", rls: "DEB9" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libmagickcore-dev", ver: "8:6.9.7.4+dfsg-11+deb9u1", rls: "DEB9" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libmagickwand-6-headers", ver: "8:6.9.7.4+dfsg-11+deb9u1", rls: "DEB9" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libmagickwand-6.q16-3", ver: "8:6.9.7.4+dfsg-11+deb9u1", rls: "DEB9" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libmagickwand-6.q16-dev", ver: "8:6.9.7.4+dfsg-11+deb9u1", rls: "DEB9" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libmagickwand-6.q16hdri-3", ver: "8:6.9.7.4+dfsg-11+deb9u1", rls: "DEB9" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libmagickwand-6.q16hdri-dev", ver: "8:6.9.7.4+dfsg-11+deb9u1", rls: "DEB9" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libmagickwand-dev", ver: "8:6.9.7.4+dfsg-11+deb9u1", rls: "DEB9" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "perlmagick", ver: "8:6.9.7.4+dfsg-11+deb9u1", rls: "DEB9" ) ) != NULL){
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

