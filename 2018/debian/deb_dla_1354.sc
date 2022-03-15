if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.891354" );
	script_version( "2021-06-16T02:00:28+0000" );
	script_cve_id( "CVE-2018-5268", "CVE-2018-5269" );
	script_name( "Debian LTS: Security Advisory for opencv (DLA-1354-1)" );
	script_tag( name: "last_modification", value: "2021-06-16 02:00:28 +0000 (Wed, 16 Jun 2021)" );
	script_tag( name: "creation_date", value: "2018-04-19 00:00:00 +0200 (Thu, 19 Apr 2018)" );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:N/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-08-24 17:37:00 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	script_xref( name: "URL", value: "https://lists.debian.org/debian-lts-announce/2018/04/msg00019.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH http://greenbone.net" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB7" );
	script_tag( name: "affected", value: "opencv on Debian Linux" );
	script_tag( name: "solution", value: "For Debian 7 'Wheezy', these problems have been fixed in version
2.3.1-11+deb7u4.

We recommend that you upgrade your opencv packages." );
	script_tag( name: "summary", value: "Two vulnerabilities were found in OpenCV, the 'Open Computer Vision
Library'.

CVE-2018-5268

In OpenCV 3.3.1, a heap-based buffer overflow happens in
cv::Jpeg2KDecoder::readComponent8u in
modules/imgcodecs/src/grfmt_jpeg2000.cpp when parsing a crafted
image file.

CVE-2018-5269

In OpenCV 3.3.1, an assertion failure happens in
cv::RBaseStream::setPos in modules/imgcodecs/src/bitstrm.cpp
because of an incorrect integer cast." );
	script_tag( name: "vuldetect", value: "This check tests the installed software version using the apt package manager." );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(!isnull( res = isdpkgvuln( pkg: "libcv-dev", ver: "2.3.1-11+deb7u4", rls: "DEB7" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libcv2.3", ver: "2.3.1-11+deb7u4", rls: "DEB7" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libcvaux-dev", ver: "2.3.1-11+deb7u4", rls: "DEB7" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libcvaux2.3", ver: "2.3.1-11+deb7u4", rls: "DEB7" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libhighgui-dev", ver: "2.3.1-11+deb7u4", rls: "DEB7" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libhighgui2.3", ver: "2.3.1-11+deb7u4", rls: "DEB7" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libopencv-calib3d-dev", ver: "2.3.1-11+deb7u4", rls: "DEB7" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libopencv-calib3d2.3", ver: "2.3.1-11+deb7u4", rls: "DEB7" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libopencv-contrib-dev", ver: "2.3.1-11+deb7u4", rls: "DEB7" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libopencv-contrib2.3", ver: "2.3.1-11+deb7u4", rls: "DEB7" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libopencv-core-dev", ver: "2.3.1-11+deb7u4", rls: "DEB7" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libopencv-core2.3", ver: "2.3.1-11+deb7u4", rls: "DEB7" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libopencv-dev", ver: "2.3.1-11+deb7u4", rls: "DEB7" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libopencv-features2d-dev", ver: "2.3.1-11+deb7u4", rls: "DEB7" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libopencv-features2d2.3", ver: "2.3.1-11+deb7u4", rls: "DEB7" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libopencv-flann-dev", ver: "2.3.1-11+deb7u4", rls: "DEB7" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libopencv-flann2.3", ver: "2.3.1-11+deb7u4", rls: "DEB7" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libopencv-gpu-dev", ver: "2.3.1-11+deb7u4", rls: "DEB7" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libopencv-gpu2.3", ver: "2.3.1-11+deb7u4", rls: "DEB7" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libopencv-highgui-dev", ver: "2.3.1-11+deb7u4", rls: "DEB7" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libopencv-highgui2.3", ver: "2.3.1-11+deb7u4", rls: "DEB7" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libopencv-imgproc-dev", ver: "2.3.1-11+deb7u4", rls: "DEB7" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libopencv-imgproc2.3", ver: "2.3.1-11+deb7u4", rls: "DEB7" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libopencv-legacy-dev", ver: "2.3.1-11+deb7u4", rls: "DEB7" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libopencv-legacy2.3", ver: "2.3.1-11+deb7u4", rls: "DEB7" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libopencv-ml-dev", ver: "2.3.1-11+deb7u4", rls: "DEB7" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libopencv-ml2.3", ver: "2.3.1-11+deb7u4", rls: "DEB7" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libopencv-objdetect-dev", ver: "2.3.1-11+deb7u4", rls: "DEB7" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libopencv-objdetect2.3", ver: "2.3.1-11+deb7u4", rls: "DEB7" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libopencv-video-dev", ver: "2.3.1-11+deb7u4", rls: "DEB7" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libopencv-video2.3", ver: "2.3.1-11+deb7u4", rls: "DEB7" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "opencv-doc", ver: "2.3.1-11+deb7u4", rls: "DEB7" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "python-opencv", ver: "2.3.1-11+deb7u4", rls: "DEB7" ) )){
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

