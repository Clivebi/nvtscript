if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.891654" );
	script_version( "2020-01-29T08:22:52+0000" );
	script_cve_id( "CVE-2014-8542", "CVE-2015-1207", "CVE-2017-14169", "CVE-2017-14223", "CVE-2017-7863", "CVE-2017-7865" );
	script_name( "Debian LTS: Security Advisory for libav (DLA-1654-1)" );
	script_tag( name: "last_modification", value: "2020-01-29 08:22:52 +0000 (Wed, 29 Jan 2020)" );
	script_tag( name: "creation_date", value: "2019-02-06 00:00:00 +0100 (Wed, 06 Feb 2019)" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	script_xref( name: "URL", value: "https://lists.debian.org/debian-lts-announce/2019/02/msg00005.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2019 Greenbone Networks GmbH" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB8" );
	script_tag( name: "affected", value: "libav on Debian Linux" );
	script_tag( name: "solution", value: "For Debian 8 'Jessie', these problems have been fixed in version
6:11.12-1~deb8u5.

We recommend that you upgrade your libav packages." );
	script_tag( name: "summary", value: "Several security issues have been corrected in multiple demuxers and
decoders of the libav multimedia library.

CVE-2014-8542

libavcodec/utils.c omitted a certain codec ID during enforcement of
alignment, which allowed remote attackers to cause a denial of ervice
(out-of-bounds access) or possibly have unspecified other impact via
crafted JV data.

CVE-2015-1207

Double-free vulnerability in libavformat/mov.c allowed remote
attackers to cause a denial of service (memory corruption and crash)
via a crafted .m4a file.

CVE-2017-7863

libav had an out-of-bounds write caused by a heap-based buffer
overflow related to the decode_frame_common function in
libavcodec/pngdec.c.

CVE-2017-7865

libav had an out-of-bounds write caused by a heap-based buffer
overflow related to the ipvideo_decode_block_opcode_0xA function in
libavcodec/interplayvideo.c and the avcodec_align_dimensions2
function in libavcodec/utils.c.

CVE-2017-14169

In the mxf_read_primer_pack function in libavformat/mxfdec.c in, an
integer signedness error might have occurred when a crafted file,
claiming a large 'item_num' field such as 0xffffffff, was provided.
As a result, the variable 'item_num' turned negative, bypassing the
check for a large value.

CVE-2017-14223

In libavformat/asfdec_f.c a DoS in asf_build_simple_index() due to
lack of an EOF (End of File) check might have caused huge CPU
consumption. When a crafted ASF file, claiming a large 'ict' field in
the header but not containing sufficient backing data, was provided,
the for loop would have consumed huge CPU and memory resources, since
there was no EOF check inside the loop." );
	script_tag( name: "vuldetect", value: "This check tests the installed software version using the apt package manager." );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(!isnull( res = isdpkgvuln( pkg: "libav-dbg", ver: "6:11.12-1~deb8u5", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libav-doc", ver: "6:11.12-1~deb8u5", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libav-tools", ver: "6:11.12-1~deb8u5", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libavcodec-dev", ver: "6:11.12-1~deb8u5", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libavcodec-extra", ver: "6:11.12-1~deb8u5", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libavcodec-extra-56", ver: "6:11.12-1~deb8u5", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libavcodec56", ver: "6:11.12-1~deb8u5", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libavdevice-dev", ver: "6:11.12-1~deb8u5", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libavdevice55", ver: "6:11.12-1~deb8u5", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libavfilter-dev", ver: "6:11.12-1~deb8u5", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libavfilter5", ver: "6:11.12-1~deb8u5", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libavformat-dev", ver: "6:11.12-1~deb8u5", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libavformat56", ver: "6:11.12-1~deb8u5", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libavresample-dev", ver: "6:11.12-1~deb8u5", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libavresample2", ver: "6:11.12-1~deb8u5", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libavutil-dev", ver: "6:11.12-1~deb8u5", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libavutil54", ver: "6:11.12-1~deb8u5", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libswscale-dev", ver: "6:11.12-1~deb8u5", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libswscale3", ver: "6:11.12-1~deb8u5", rls: "DEB8" ) )){
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

