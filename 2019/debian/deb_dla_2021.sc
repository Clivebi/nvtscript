if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.892021" );
	script_version( "2021-09-02T14:01:33+0000" );
	script_cve_id( "CVE-2017-17127", "CVE-2017-18245", "CVE-2018-19128", "CVE-2018-19130", "CVE-2019-14443", "CVE-2019-17542" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2021-09-02 14:01:33 +0000 (Thu, 02 Sep 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-04-07 17:06:00 +0000 (Wed, 07 Apr 2021)" );
	script_tag( name: "creation_date", value: "2019-12-06 03:00:15 +0000 (Fri, 06 Dec 2019)" );
	script_name( "Debian LTS: Security Advisory for libav (DLA-2021-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2019 Greenbone Networks GmbH" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB8" );
	script_xref( name: "URL", value: "https://lists.debian.org/debian-lts-announce/2019/12/msg00003.html" );
	script_xref( name: "URL", value: "https://security-tracker.debian.org/tracker/DLA-2021-1" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'libav'
  package(s) announced via the DLA-2021-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "Several security issues were fixed in libav, a multimedia library for
processing audio and video files.

CVE-2017-17127

The vc1_decode_frame function in libavcodec/vc1dec.c allows remote
attackers to cause a denial of service (NULL pointer dereference
and application crash) via a crafted file.
CVE-2018-19130 is a duplicate of this vulnerability.

CVE-2017-18245

The mpc8_probe function in libavformat/mpc8.c allows remote
attackers to cause a denial of service (heap-based buffer
over-read) via a crafted audio file on 32-bit systems.

CVE-2018-19128

Heap-based buffer over-read in decode_frame in libavcodec/lcldec.c
allows an attacker to cause denial-of-service via a crafted avi
file.

CVE-2019-14443

Division by zero in range_decode_culshift in libavcodec/apedec.c
allows remote attackers to cause a denial of service (application
crash), as demonstrated by avconv.

CVE-2019-17542

Heap-based buffer overflow in vqa_decode_chunk because of an
out-of-array access in vqa_decode_init in libavcodec/vqavideo.c." );
	script_tag( name: "affected", value: "'libav' package(s) on Debian Linux." );
	script_tag( name: "solution", value: "For Debian 8 'Jessie', these problems have been fixed in version
6:11.12-1~deb8u9.

We recommend that you upgrade your libav packages." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(!isnull( res = isdpkgvuln( pkg: "libav-dbg", ver: "6:11.12-1~deb8u9", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libav-doc", ver: "6:11.12-1~deb8u9", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libav-tools", ver: "6:11.12-1~deb8u9", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libavcodec-dev", ver: "6:11.12-1~deb8u9", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libavcodec-extra", ver: "6:11.12-1~deb8u9", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libavcodec-extra-56", ver: "6:11.12-1~deb8u9", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libavcodec56", ver: "6:11.12-1~deb8u9", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libavdevice-dev", ver: "6:11.12-1~deb8u9", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libavdevice55", ver: "6:11.12-1~deb8u9", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libavfilter-dev", ver: "6:11.12-1~deb8u9", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libavfilter5", ver: "6:11.12-1~deb8u9", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libavformat-dev", ver: "6:11.12-1~deb8u9", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libavformat56", ver: "6:11.12-1~deb8u9", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libavresample-dev", ver: "6:11.12-1~deb8u9", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libavresample2", ver: "6:11.12-1~deb8u9", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libavutil-dev", ver: "6:11.12-1~deb8u9", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libavutil54", ver: "6:11.12-1~deb8u9", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libswscale-dev", ver: "6:11.12-1~deb8u9", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libswscale3", ver: "6:11.12-1~deb8u9", rls: "DEB8" ) )){
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

