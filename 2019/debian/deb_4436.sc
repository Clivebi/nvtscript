if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.704436" );
	script_version( "2021-09-03T10:01:28+0000" );
	script_cve_id( "CVE-2019-10650", "CVE-2019-9956" );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2021-09-03 10:01:28 +0000 (Fri, 03 Sep 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-08-24 17:37:00 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2019-04-29 02:00:11 +0000 (Mon, 29 Apr 2019)" );
	script_name( "Debian Security Advisory DSA 4436-1 (imagemagick - security update)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2019 Greenbone Networks GmbH" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB9" );
	script_xref( name: "URL", value: "https://www.debian.org/security/2019/dsa-4436.html" );
	script_xref( name: "URL", value: "https://security-tracker.debian.org/tracker/DSA-4436-1" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'imagemagick'
  package(s) announced via the DSA-4436-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "This update fixes two vulnerabilities in Imagemagick: Memory handling
problems and missing or incomplete input sanitising may result in denial
of service, memory disclosure or the execution of arbitrary code if
malformed TIFF or Postscript files are processed." );
	script_tag( name: "affected", value: "'imagemagick' package(s) on Debian Linux." );
	script_tag( name: "solution", value: "For the stable distribution (stretch), these problems have been fixed in
version 8:6.9.7.4+dfsg-11+deb9u7.

We recommend that you upgrade your imagemagick packages." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(!isnull( res = isdpkgvuln( pkg: "imagemagick", ver: "8:6.9.7.4+dfsg-11+deb9u7", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "imagemagick-6-common", ver: "8:6.9.7.4+dfsg-11+deb9u7", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "imagemagick-6-doc", ver: "8:6.9.7.4+dfsg-11+deb9u7", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "imagemagick-6.q16", ver: "8:6.9.7.4+dfsg-11+deb9u7", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "imagemagick-6.q16hdri", ver: "8:6.9.7.4+dfsg-11+deb9u7", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "imagemagick-common", ver: "8:6.9.7.4+dfsg-11+deb9u7", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "imagemagick-doc", ver: "8:6.9.7.4+dfsg-11+deb9u7", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libimage-magick-perl", ver: "8:6.9.7.4+dfsg-11+deb9u7", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libimage-magick-q16-perl", ver: "8:6.9.7.4+dfsg-11+deb9u7", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libimage-magick-q16hdri-perl", ver: "8:6.9.7.4+dfsg-11+deb9u7", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libmagick++-6-headers", ver: "8:6.9.7.4+dfsg-11+deb9u7", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libmagick++-6.q16-7", ver: "8:6.9.7.4+dfsg-11+deb9u7", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libmagick++-6.q16-dev", ver: "8:6.9.7.4+dfsg-11+deb9u7", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libmagick++-6.q16hdri-7", ver: "8:6.9.7.4+dfsg-11+deb9u7", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libmagick++-6.q16hdri-dev", ver: "8:6.9.7.4+dfsg-11+deb9u7", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libmagick++-dev", ver: "8:6.9.7.4+dfsg-11+deb9u7", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libmagickcore-6-arch-config", ver: "8:6.9.7.4+dfsg-11+deb9u7", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libmagickcore-6-headers", ver: "8:6.9.7.4+dfsg-11+deb9u7", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libmagickcore-6.q16-3", ver: "8:6.9.7.4+dfsg-11+deb9u7", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libmagickcore-6.q16-3-extra", ver: "8:6.9.7.4+dfsg-11+deb9u7", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libmagickcore-6.q16-dev", ver: "8:6.9.7.4+dfsg-11+deb9u7", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libmagickcore-6.q16hdri-3", ver: "8:6.9.7.4+dfsg-11+deb9u7", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libmagickcore-6.q16hdri-3-extra", ver: "8:6.9.7.4+dfsg-11+deb9u7", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libmagickcore-6.q16hdri-dev", ver: "8:6.9.7.4+dfsg-11+deb9u7", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libmagickcore-dev", ver: "8:6.9.7.4+dfsg-11+deb9u7", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libmagickwand-6-headers", ver: "8:6.9.7.4+dfsg-11+deb9u7", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libmagickwand-6.q16-3", ver: "8:6.9.7.4+dfsg-11+deb9u7", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libmagickwand-6.q16-dev", ver: "8:6.9.7.4+dfsg-11+deb9u7", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libmagickwand-6.q16hdri-3", ver: "8:6.9.7.4+dfsg-11+deb9u7", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libmagickwand-6.q16hdri-dev", ver: "8:6.9.7.4+dfsg-11+deb9u7", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libmagickwand-dev", ver: "8:6.9.7.4+dfsg-11+deb9u7", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "perlmagick", ver: "8:6.9.7.4+dfsg-11+deb9u7", rls: "DEB9" ) )){
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

