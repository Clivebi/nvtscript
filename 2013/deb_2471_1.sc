if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.702471" );
	script_version( "2020-10-05T06:02:24+0000" );
	script_cve_id( "CVE-2011-3893", "CVE-2011-3895", "CVE-2011-3936", "CVE-2012-0947", "CVE-2011-3892", "CVE-2011-3929", "CVE-2011-3940", "CVE-2011-3947", "CVE-2012-0853" );
	script_name( "Debian Security Advisory DSA 2471-1 (ffmpeg - several vulnerabilities)" );
	script_tag( name: "last_modification", value: "2020-10-05 06:02:24 +0000 (Mon, 05 Oct 2020)" );
	script_tag( name: "creation_date", value: "2013-09-18 11:53:02 +0200 (Wed, 18 Sep 2013)" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_xref( name: "URL", value: "http://www.debian.org/security/2012/dsa-2471.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2013 Greenbone Networks GmbH http://greenbone.net" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB6" );
	script_tag( name: "affected", value: "ffmpeg on Debian Linux" );
	script_tag( name: "solution", value: "For the stable distribution (squeeze), this problem has been fixed in
version 4:0.5.8-1.

For the unstable distribution (sid), this problem has been fixed in
version 6:0.8.2-1 of libav.

We recommend that you upgrade your ffmpeg packages." );
	script_tag( name: "summary", value: "Several vulnerabilities have been discovered in FFmpeg, a multimedia
player, server and encoder. Multiple input validations in the decoders/
demuxers for Westwood Studios VQA, Apple MJPEG-B, Theora, Matroska,
Vorbis, Sony ATRAC3, DV, NSV, files could lead to the execution of
arbitrary code.

These issues were discovered by Aki Helin, Mateusz Jurczyk, Gynvael
Coldwind, and Michael Niedermayer." );
	script_tag( name: "vuldetect", value: "This check tests the installed software version using the apt package manager." );
	script_tag( name: "qod_type", value: "package" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(( res = isdpkgvuln( pkg: "ffmpeg", ver: "4:0.5.8-1", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "ffmpeg-dbg", ver: "4:0.5.8-1", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "ffmpeg-doc", ver: "4:0.5.8-1", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libavcodec-dev", ver: "4:0.5.8-1", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libavcodec52", ver: "4:0.5.8-1", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libavdevice-dev", ver: "4:0.5.8-1", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libavdevice52", ver: "4:0.5.8-1", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libavfilter-dev", ver: "4:0.5.8-1", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libavfilter0", ver: "4:0.5.8-1", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libavformat-dev", ver: "4:0.5.8-1", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libavformat52", ver: "4:0.5.8-1", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libavutil-dev", ver: "4:0.5.8-1", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libavutil49", ver: "4:0.5.8-1", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libpostproc-dev", ver: "4:0.5.8-1", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libpostproc51", ver: "4:0.5.8-1", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libswscale-dev", ver: "4:0.5.8-1", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libswscale0", ver: "4:0.5.8-1", rls: "DEB6" ) ) != NULL){
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

