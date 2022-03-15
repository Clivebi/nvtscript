if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.70554" );
	script_tag( name: "cvss_base", value: "9.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:C/I:C/A:C" );
	script_cve_id( "CVE-2011-3362", "CVE-2011-3973", "CVE-2011-3974", "CVE-2011-3504" );
	script_version( "$Revision: 14275 $" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-18 15:39:45 +0100 (Mon, 18 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2012-02-11 02:28:41 -0500 (Sat, 11 Feb 2012)" );
	script_name( "Debian Security Advisory DSA 2336-1 (ffmpeg)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2012 E-Soft Inc. http://www.securityspace.com" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB6" );
	script_xref( name: "URL", value: "https://secure1.securityspace.com/smysecure/catid.html?in=DSA%202336-1" );
	script_tag( name: "insight", value: "Multiple vulnerabilities were found in the ffmpeg, a multimedia player,
server and encoder:

CVE-2011-3362

An integer signedness error in decode_residual_block function of
the Chinese AVS video (CAVS) decoder in libavcodec can lead to
denial of service (memory corruption and application crash) or
possible code execution via a crafted CAVS file.

CVE-2011-3973/CVE-2011-3974

Multiple errors in the Chinese AVS video (CAVS) decoder can lead to
denial of service (memory corruption and application crash) via an
invalid bitstream.

CVE-2011-3504

A memory allocation problem in the Matroska format decoder can lead
to code execution via a crafted file.

For the stable distribution (squeeze), this problem has been fixed in
version 4:0.5.5-1.

For the unstable distribution (sid), this problem has been fixed in
version 4:0.7.2-1 of the libav source package.

Security support for ffmpeg has been discontinued for the oldstable
distribution (lenny) before in DSA 2306.
The current version in oldstable is not supported by upstream anymore
and is affected by several security issues. Backporting fixes for these
and any future issues has become unfeasible and therefore we needed to
drop our security support for the version in oldstable." );
	script_tag( name: "solution", value: "We recommend that you upgrade your ffmpeg packages." );
	script_tag( name: "summary", value: "The remote host is missing an update to ffmpeg
announced via advisory DSA 2336-1." );
	script_tag( name: "qod_type", value: "package" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(( res = isdpkgvuln( pkg: "ffmpeg", ver: "4:0.5.5-1", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "ffmpeg-dbg", ver: "4:0.5.5-1", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "ffmpeg-doc", ver: "4:0.5.5-1", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libavcodec-dev", ver: "4:0.5.5-1", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libavcodec52", ver: "4:0.5.5-1", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libavdevice-dev", ver: "4:0.5.5-1", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libavdevice52", ver: "4:0.5.5-1", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libavfilter-dev", ver: "4:0.5.5-1", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libavfilter0", ver: "4:0.5.5-1", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libavformat-dev", ver: "4:0.5.5-1", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libavformat52", ver: "4:0.5.5-1", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libavutil-dev", ver: "4:0.5.5-1", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libavutil49", ver: "4:0.5.5-1", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libpostproc-dev", ver: "4:0.5.5-1", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libpostproc51", ver: "4:0.5.5-1", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libswscale-dev", ver: "4:0.5.5-1", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libswscale0", ver: "4:0.5.5-1", rls: "DEB6" ) ) != NULL){
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

