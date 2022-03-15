if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.891888" );
	script_version( "2021-09-06T10:01:39+0000" );
	script_cve_id( "CVE-2019-12974", "CVE-2019-13135", "CVE-2019-13295", "CVE-2019-13297", "CVE-2019-13304", "CVE-2019-13305", "CVE-2019-13306" );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2021-09-06 10:01:39 +0000 (Mon, 06 Sep 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-04-28 18:22:00 +0000 (Wed, 28 Apr 2021)" );
	script_tag( name: "creation_date", value: "2019-08-17 02:00:15 +0000 (Sat, 17 Aug 2019)" );
	script_name( "Debian LTS: Security Advisory for imagemagick (DLA-1888-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2019 Greenbone Networks GmbH" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB8" );
	script_xref( name: "URL", value: "https://lists.debian.org/debian-lts-announce/2019/08/msg00021.html" );
	script_xref( name: "URL", value: "https://security-tracker.debian.org/tracker/DLA-1888-1" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'imagemagick'
  package(s) announced via the DLA-1888-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "Multiple vulnerabilities have been found in imagemagick, an image processing
toolkit.

CVE-2019-12974

NULL pointer dereference in ReadPANGOImage and ReadVIDImage (coders/pango.c
and coders/vid.c). This vulnerability might be leveraged by remote attackers
to cause denial of service via crafted image data.

CVE-2019-13135

Multiple use of uninitialized values in ReadCUTImage, UnpackWPG2Raster and
UnpackWPGRaster (coders/wpg.c and coders/cut.c). These vulnerabilities might
be leveraged by remote attackers to cause denial of service or unauthorized
disclosure or modification of information via crafted image data.

CVE-2019-13295, CVE-2019-13297

Multiple heap buffer over-reads in AdaptiveThresholdImage
(magick/threshold.c). These vulnerabilities might be leveraged by remote
attackers to cause denial of service or unauthorized disclosure or
modification of information via crafted image data.

CVE-2019-13304, CVE-2019-13305, CVE-2019-13306

Multiple stack buffer overflows in WritePNMImage (coders/pnm.c), leading to
stack buffer over write up to ten bytes. Remote attackers might leverage
these flaws to potentially perform code execution or denial of service." );
	script_tag( name: "affected", value: "'imagemagick' package(s) on Debian Linux." );
	script_tag( name: "solution", value: "For Debian 8 'Jessie', these problems have been fixed in version
8:6.8.9.9-5+deb8u17.

We recommend that you upgrade your imagemagick packages." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(!isnull( res = isdpkgvuln( pkg: "imagemagick", ver: "8:6.8.9.9-5+deb8u17", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "imagemagick-6.q16", ver: "8:6.8.9.9-5+deb8u17", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "imagemagick-common", ver: "8:6.8.9.9-5+deb8u17", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "imagemagick-dbg", ver: "8:6.8.9.9-5+deb8u17", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "imagemagick-doc", ver: "8:6.8.9.9-5+deb8u17", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libimage-magick-perl", ver: "8:6.8.9.9-5+deb8u17", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libimage-magick-q16-perl", ver: "8:6.8.9.9-5+deb8u17", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libmagick++-6-headers", ver: "8:6.8.9.9-5+deb8u17", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libmagick++-6.q16-5", ver: "8:6.8.9.9-5+deb8u17", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libmagick++-6.q16-dev", ver: "8:6.8.9.9-5+deb8u17", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libmagick++-dev", ver: "8:6.8.9.9-5+deb8u17", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libmagickcore-6-arch-config", ver: "8:6.8.9.9-5+deb8u17", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libmagickcore-6-headers", ver: "8:6.8.9.9-5+deb8u17", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libmagickcore-6.q16-2", ver: "8:6.8.9.9-5+deb8u17", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libmagickcore-6.q16-2-extra", ver: "8:6.8.9.9-5+deb8u17", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libmagickcore-6.q16-dev", ver: "8:6.8.9.9-5+deb8u17", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libmagickcore-dev", ver: "8:6.8.9.9-5+deb8u17", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libmagickwand-6-headers", ver: "8:6.8.9.9-5+deb8u17", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libmagickwand-6.q16-2", ver: "8:6.8.9.9-5+deb8u17", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libmagickwand-6.q16-dev", ver: "8:6.8.9.9-5+deb8u17", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libmagickwand-dev", ver: "8:6.8.9.9-5+deb8u17", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "perlmagick", ver: "8:6.8.9.9-5+deb8u17", rls: "DEB8" ) )){
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
exit( 0 );

