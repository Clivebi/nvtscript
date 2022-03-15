if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.704715" );
	script_version( "2021-07-28T02:00:54+0000" );
	script_cve_id( "CVE-2019-13300", "CVE-2019-13304", "CVE-2019-13306", "CVE-2019-13307", "CVE-2019-15140", "CVE-2019-19948" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2021-07-28 02:00:54 +0000 (Wed, 28 Jul 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-09-30 20:15:00 +0000 (Wed, 30 Sep 2020)" );
	script_tag( name: "creation_date", value: "2020-07-04 03:11:30 +0000 (Sat, 04 Jul 2020)" );
	script_name( "Debian: Security Advisory for imagemagick (DSA-4715-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB9" );
	script_xref( name: "URL", value: "https://www.debian.org/security/2020/dsa-4715.html" );
	script_xref( name: "URL", value: "https://security-tracker.debian.org/tracker/DSA-4715-1" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'imagemagick'
  package(s) announced via the DSA-4715-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "This update fixes multiple vulnerabilities in Imagemagick: Various memory
handling problems and cases of missing or incomplete input sanitising
may result in denial of service, memory disclosure or potentially the
execution of arbitrary code if malformed image files are processed." );
	script_tag( name: "affected", value: "'imagemagick' package(s) on Debian Linux." );
	script_tag( name: "solution", value: "For the oldstable distribution (stretch), these problems have been fixed
in version 8:6.9.7.4+dfsg-11+deb9u8.

We recommend that you upgrade your imagemagick packages." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(!isnull( res = isdpkgvuln( pkg: "imagemagick", ver: "8:6.9.7.4+dfsg-11+deb9u8", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "imagemagick-6-common", ver: "8:6.9.7.4+dfsg-11+deb9u8", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "imagemagick-6-doc", ver: "8:6.9.7.4+dfsg-11+deb9u8", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "imagemagick-6.q16", ver: "8:6.9.7.4+dfsg-11+deb9u8", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "imagemagick-6.q16hdri", ver: "8:6.9.7.4+dfsg-11+deb9u8", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "imagemagick-common", ver: "8:6.9.7.4+dfsg-11+deb9u8", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "imagemagick-doc", ver: "8:6.9.7.4+dfsg-11+deb9u8", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libimage-magick-perl", ver: "8:6.9.7.4+dfsg-11+deb9u8", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libimage-magick-q16-perl", ver: "8:6.9.7.4+dfsg-11+deb9u8", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libimage-magick-q16hdri-perl", ver: "8:6.9.7.4+dfsg-11+deb9u8", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libmagick++-6-headers", ver: "8:6.9.7.4+dfsg-11+deb9u8", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libmagick++-6.q16-7", ver: "8:6.9.7.4+dfsg-11+deb9u8", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libmagick++-6.q16-dev", ver: "8:6.9.7.4+dfsg-11+deb9u8", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libmagick++-6.q16hdri-7", ver: "8:6.9.7.4+dfsg-11+deb9u8", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libmagick++-6.q16hdri-dev", ver: "8:6.9.7.4+dfsg-11+deb9u8", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libmagick++-dev", ver: "8:6.9.7.4+dfsg-11+deb9u8", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libmagickcore-6-arch-config", ver: "8:6.9.7.4+dfsg-11+deb9u8", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libmagickcore-6-headers", ver: "8:6.9.7.4+dfsg-11+deb9u8", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libmagickcore-6.q16-3", ver: "8:6.9.7.4+dfsg-11+deb9u8", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libmagickcore-6.q16-3-extra", ver: "8:6.9.7.4+dfsg-11+deb9u8", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libmagickcore-6.q16-dev", ver: "8:6.9.7.4+dfsg-11+deb9u8", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libmagickcore-6.q16hdri-3", ver: "8:6.9.7.4+dfsg-11+deb9u8", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libmagickcore-6.q16hdri-3-extra", ver: "8:6.9.7.4+dfsg-11+deb9u8", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libmagickcore-6.q16hdri-dev", ver: "8:6.9.7.4+dfsg-11+deb9u8", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libmagickcore-dev", ver: "8:6.9.7.4+dfsg-11+deb9u8", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libmagickwand-6-headers", ver: "8:6.9.7.4+dfsg-11+deb9u8", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libmagickwand-6.q16-3", ver: "8:6.9.7.4+dfsg-11+deb9u8", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libmagickwand-6.q16-dev", ver: "8:6.9.7.4+dfsg-11+deb9u8", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libmagickwand-6.q16hdri-3", ver: "8:6.9.7.4+dfsg-11+deb9u8", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libmagickwand-6.q16hdri-dev", ver: "8:6.9.7.4+dfsg-11+deb9u8", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libmagickwand-dev", ver: "8:6.9.7.4+dfsg-11+deb9u8", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "perlmagick", ver: "8:6.9.7.4+dfsg-11+deb9u8", rls: "DEB9" ) )){
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

