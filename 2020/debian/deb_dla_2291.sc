if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.892291" );
	script_version( "2021-07-23T11:01:09+0000" );
	script_cve_id( "CVE-2019-13390", "CVE-2019-17542", "CVE-2020-13904" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2021-07-23 11:01:09 +0000 (Fri, 23 Jul 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-04-07 17:06:00 +0000 (Wed, 07 Apr 2021)" );
	script_tag( name: "creation_date", value: "2020-07-28 03:00:08 +0000 (Tue, 28 Jul 2020)" );
	script_name( "Debian LTS: Security Advisory for ffmpeg (DLA-2291-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB9" );
	script_xref( name: "URL", value: "https://lists.debian.org/debian-lts-announce/2020/07/msg00022.html" );
	script_xref( name: "URL", value: "https://security-tracker.debian.org/tracker/DLA-2291-1" );
	script_xref( name: "URL", value: "https://git.ffmpeg.org/gitweb/ffmpeg.git/blob/37a8ad9a3167923d500910031a8086489c004d83:/Changelog" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'ffmpeg'
  package(s) announced via the DLA-2291-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "Several vulnerabilities have been fixed by upgrading FFmpeg,
a widely used multimedia framework, from 3.2.14 to 3.2.15.

CVE-2019-13390

rawenc: Only accept the appropriate stream type for raw muxers.

CVE-2019-17542

Heap-based buffer overflow in vqa_decode_chunk.

CVE-2020-13904

Use-after-free via a crafted EXTINF duration in an m3u8 file." );
	script_tag( name: "affected", value: "'ffmpeg' package(s) on Debian Linux." );
	script_tag( name: "solution", value: "For Debian 9 stretch, these problems have been fixed in version
7:3.2.15-0+deb9u1.

Several other bugs are also fixed in 3.2.15,
a full list of changes is available at the linked references.

We recommend that you upgrade your ffmpeg packages." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(!isnull( res = isdpkgvuln( pkg: "ffmpeg", ver: "7:3.2.15-0+deb9u1", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "ffmpeg-doc", ver: "7:3.2.15-0+deb9u1", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libav-tools", ver: "7:3.2.15-0+deb9u1", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libavcodec-dev", ver: "7:3.2.15-0+deb9u1", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libavcodec-extra", ver: "7:3.2.15-0+deb9u1", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libavcodec-extra57", ver: "7:3.2.15-0+deb9u1", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libavcodec57", ver: "7:3.2.15-0+deb9u1", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libavdevice-dev", ver: "7:3.2.15-0+deb9u1", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libavdevice57", ver: "7:3.2.15-0+deb9u1", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libavfilter-dev", ver: "7:3.2.15-0+deb9u1", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libavfilter-extra", ver: "7:3.2.15-0+deb9u1", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libavfilter-extra6", ver: "7:3.2.15-0+deb9u1", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libavfilter6", ver: "7:3.2.15-0+deb9u1", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libavformat-dev", ver: "7:3.2.15-0+deb9u1", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libavformat57", ver: "7:3.2.15-0+deb9u1", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libavresample-dev", ver: "7:3.2.15-0+deb9u1", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libavresample3", ver: "7:3.2.15-0+deb9u1", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libavutil-dev", ver: "7:3.2.15-0+deb9u1", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libavutil55", ver: "7:3.2.15-0+deb9u1", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libpostproc-dev", ver: "7:3.2.15-0+deb9u1", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libpostproc54", ver: "7:3.2.15-0+deb9u1", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libswresample-dev", ver: "7:3.2.15-0+deb9u1", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libswresample2", ver: "7:3.2.15-0+deb9u1", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libswscale-dev", ver: "7:3.2.15-0+deb9u1", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libswscale4", ver: "7:3.2.15-0+deb9u1", rls: "DEB9" ) )){
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

