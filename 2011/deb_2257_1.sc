if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.69964" );
	script_version( "$Revision: 14275 $" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-18 15:39:45 +0100 (Mon, 18 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2011-08-03 04:36:20 +0200 (Wed, 03 Aug 2011)" );
	script_cve_id( "CVE-2011-2194" );
	script_tag( name: "cvss_base", value: "9.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:C/I:C/A:C" );
	script_name( "Debian Security Advisory DSA 2257-1 (vlc)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2011 E-Soft Inc. http://www.securityspace.com" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB6" );
	script_xref( name: "URL", value: "https://secure1.securityspace.com/smysecure/catid.html?in=DSA%202257-1" );
	script_tag( name: "insight", value: "Rocco Calvi discovered that the XSPF playlist parser of vlc, a multimedia
player and streamer, is prone to an integer overflow resulting in a
heap-based buffer overflow.  This might allow an attacker to execute
arbitrary code by tricking a victim into opening a specially crafted
file.


The oldstable distribution (lenny) is not affected by this problem.

For the stable distribution (squeeze), this problem has been fixed in
version 1.1.3-1squeeze6.

For the testing (wheezy) and unstable (sid) distributions, this
problem will be fixed soon." );
	script_tag( name: "solution", value: "We recommend that you upgrade your vlc packages." );
	script_tag( name: "summary", value: "The remote host is missing an update to vlc
announced via advisory DSA 2257-1." );
	script_tag( name: "qod_type", value: "package" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(( res = isdpkgvuln( pkg: "libvlc-dev", ver: "1.1.3-1squeeze6", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libvlc5", ver: "1.1.3-1squeeze6", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libvlccore-dev", ver: "1.1.3-1squeeze6", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libvlccore4", ver: "1.1.3-1squeeze6", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "mozilla-plugin-vlc", ver: "1.1.3-1squeeze6", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "vlc", ver: "1.1.3-1squeeze6", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "vlc-data", ver: "1.1.3-1squeeze6", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "vlc-dbg", ver: "1.1.3-1squeeze6", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "vlc-nox", ver: "1.1.3-1squeeze6", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "vlc-plugin-fluidsynth", ver: "1.1.3-1squeeze6", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "vlc-plugin-ggi", ver: "1.1.3-1squeeze6", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "vlc-plugin-jack", ver: "1.1.3-1squeeze6", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "vlc-plugin-notify", ver: "1.1.3-1squeeze6", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "vlc-plugin-pulse", ver: "1.1.3-1squeeze6", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "vlc-plugin-sdl", ver: "1.1.3-1squeeze6", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "vlc-plugin-svg", ver: "1.1.3-1squeeze6", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "vlc-plugin-svgalib", ver: "1.1.3-1squeeze6", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "vlc-plugin-zvbi", ver: "1.1.3-1squeeze6", rls: "DEB6" ) ) != NULL){
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

