if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.71472" );
	script_cve_id( "CVE-2011-3951", "CVE-2011-3952", "CVE-2012-0851", "CVE-2012-0852" );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_version( "$Revision: 14275 $" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-18 15:39:45 +0100 (Mon, 18 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2012-08-10 03:05:54 -0400 (Fri, 10 Aug 2012)" );
	script_name( "Debian Security Advisory DSA 2494-1 (ffmpeg)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2012 E-Soft Inc. http://www.securityspace.com" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB6" );
	script_xref( name: "URL", value: "https://secure1.securityspace.com/smysecure/catid.html?in=DSA%202494-1" );
	script_tag( name: "insight", value: "It was discovered that ffmpeg, Debian's version of the libav media
codec suite, contains vulnerabilities in the DPCM codecs
(CVE-2011-3951), H.264 (CVE-2012-0851), ADPCM (CVE-2012-0852), and the
KMVC decoder (CVE-2011-3952).

In addition, this update contains bug fixes from the libav 0.5.9
upstream release.

For the stable distribution (squeeze), these problems have been fixed
in version 4:0.5.9-1.

For the unstable distribution (sid), these problems have been fixed in
version 6:0.8.3-1." );
	script_tag( name: "solution", value: "We recommend that you upgrade your ffmpeg packages." );
	script_tag( name: "summary", value: "The remote host is missing an update to ffmpeg
announced via advisory DSA 2494-1." );
	script_tag( name: "qod_type", value: "package" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(( res = isdpkgvuln( pkg: "ffmpeg", ver: "4:0.5.9-1", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "ffmpeg-dbg", ver: "4:0.5.9-1", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "ffmpeg-doc", ver: "4:0.5.9-1", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libavcodec-dev", ver: "4:0.5.9-1", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libavcodec52", ver: "4:0.5.9-1", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libavdevice-dev", ver: "4:0.5.9-1", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libavdevice52", ver: "4:0.5.9-1", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libavfilter-dev", ver: "4:0.5.9-1", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libavfilter0", ver: "4:0.5.9-1", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libavformat-dev", ver: "4:0.5.9-1", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libavformat52", ver: "4:0.5.9-1", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libavutil-dev", ver: "4:0.5.9-1", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libavutil49", ver: "4:0.5.9-1", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libpostproc-dev", ver: "4:0.5.9-1", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libpostproc51", ver: "4:0.5.9-1", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libswscale-dev", ver: "4:0.5.9-1", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libswscale0", ver: "4:0.5.9-1", rls: "DEB6" ) ) != NULL){
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

