if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.703996" );
	script_version( "2021-09-14T13:01:54+0000" );
	script_cve_id( "CVE-2017-14054", "CVE-2017-14055", "CVE-2017-14056", "CVE-2017-14057", "CVE-2017-14058", "CVE-2017-14059", "CVE-2017-14169", "CVE-2017-14170", "CVE-2017-14171", "CVE-2017-14222", "CVE-2017-14223", "CVE-2017-14225", "CVE-2017-14767" );
	script_name( "Debian Security Advisory DSA 3996-1 (ffmpeg - security update)" );
	script_tag( name: "last_modification", value: "2021-09-14 13:01:54 +0000 (Tue, 14 Sep 2021)" );
	script_tag( name: "creation_date", value: "2017-10-10 00:00:00 +0200 (Tue, 10 Oct 2017)" );
	script_tag( name: "cvss_base", value: "7.1" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:N/A:C" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-10-03 00:03:00 +0000 (Thu, 03 Oct 2019)" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	script_xref( name: "URL", value: "http://www.debian.org/security/2017/dsa-3996.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2017 Greenbone Networks GmbH" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB9" );
	script_tag( name: "affected", value: "ffmpeg on Debian Linux" );
	script_tag( name: "solution", value: "For the stable distribution (stretch), these problems have been fixed in
version 7:3.2.8-1~deb9u1.

We recommend that you upgrade your ffmpeg packages." );
	script_tag( name: "summary", value: "Several vulnerabilities have been discovered in the FFmpeg multimedia
framework, which could result in denial of service or potentially the
execution of arbitrary code if malformed Real, MV, RL2, ASF, Apple HLS,
Phantom Cine, MXF, NSV, MOV or RTP H.264 files/streams are processed." );
	script_tag( name: "vuldetect", value: "This check tests the installed software version using the apt package manager." );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(( res = isdpkgvuln( pkg: "ffmpeg", ver: "7:3.2.8-1~deb9u1", rls: "DEB9" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "ffmpeg-doc", ver: "7:3.2.8-1~deb9u1", rls: "DEB9" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libav-tools", ver: "7:3.2.8-1~deb9u1", rls: "DEB9" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libavcodec-dev", ver: "7:3.2.8-1~deb9u1", rls: "DEB9" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libavcodec-extra", ver: "7:3.2.8-1~deb9u1", rls: "DEB9" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libavcodec-extra57", ver: "7:3.2.8-1~deb9u1", rls: "DEB9" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libavcodec57", ver: "7:3.2.8-1~deb9u1", rls: "DEB9" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libavdevice-dev", ver: "7:3.2.8-1~deb9u1", rls: "DEB9" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libavdevice57", ver: "7:3.2.8-1~deb9u1", rls: "DEB9" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libavfilter-dev", ver: "7:3.2.8-1~deb9u1", rls: "DEB9" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libavfilter-extra", ver: "7:3.2.8-1~deb9u1", rls: "DEB9" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libavfilter-extra6", ver: "7:3.2.8-1~deb9u1", rls: "DEB9" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libavfilter6", ver: "7:3.2.8-1~deb9u1", rls: "DEB9" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libavformat-dev", ver: "7:3.2.8-1~deb9u1", rls: "DEB9" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libavformat57", ver: "7:3.2.8-1~deb9u1", rls: "DEB9" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libavresample-dev", ver: "7:3.2.8-1~deb9u1", rls: "DEB9" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libavresample3", ver: "7:3.2.8-1~deb9u1", rls: "DEB9" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libavutil-dev", ver: "7:3.2.8-1~deb9u1", rls: "DEB9" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libavutil55", ver: "7:3.2.8-1~deb9u1", rls: "DEB9" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libpostproc-dev", ver: "7:3.2.8-1~deb9u1", rls: "DEB9" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libpostproc54", ver: "7:3.2.8-1~deb9u1", rls: "DEB9" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libswresample-dev", ver: "7:3.2.8-1~deb9u1", rls: "DEB9" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libswresample2", ver: "7:3.2.8-1~deb9u1", rls: "DEB9" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libswscale-dev", ver: "7:3.2.8-1~deb9u1", rls: "DEB9" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libswscale4", ver: "7:3.2.8-1~deb9u1", rls: "DEB9" ) ) != NULL){
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

