if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.68993" );
	script_version( "$Revision: 14275 $" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-18 15:39:45 +0100 (Mon, 18 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2011-03-07 16:04:02 +0100 (Mon, 07 Mar 2011)" );
	script_tag( name: "cvss_base", value: "9.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:C/I:C/A:C" );
	script_cve_id( "CVE-2011-0531" );
	script_name( "Debian Security Advisory DSA 2159-1 (vlc)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2011 E-Soft Inc. http://www.securityspace.com" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB6" );
	script_xref( name: "URL", value: "https://secure1.securityspace.com/smysecure/catid.html?in=DSA%202159-1" );
	script_tag( name: "insight", value: "Dan Rosenberg discovered that insufficient input validation in VLC's
processing of Matroska/WebM containers could lead to the execution of
arbitrary code.

For the stable distribution (squeeze), this problem has been fixed in
version 1.1.3-1squeeze3.

The version of vlc in the oldstable distribution (lenny) is affected
by further issues and will be addressed in a followup DSA.

For the unstable distribution (sid), this problem has been fixed in
version 1.1.7-1." );
	script_tag( name: "solution", value: "We recommend that you upgrade your vlc packages." );
	script_tag( name: "summary", value: "The remote host is missing an update to vlc
announced via advisory DSA 2159-1." );
	script_tag( name: "qod_type", value: "package" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(( res = isdpkgvuln( pkg: "libvlc-dev", ver: "1.1.3-1squeeze3", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libvlc5", ver: "1.1.3-1squeeze3", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libvlccore-dev", ver: "1.1.3-1squeeze3", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libvlccore4", ver: "1.1.3-1squeeze3", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "mozilla-plugin-vlc", ver: "1.1.3-1squeeze3", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "vlc", ver: "1.1.3-1squeeze3", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "vlc-data", ver: "1.1.3-1squeeze3", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "vlc-dbg", ver: "1.1.3-1squeeze3", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "vlc-nox", ver: "1.1.3-1squeeze3", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "vlc-plugin-fluidsynth", ver: "1.1.3-1squeeze3", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "vlc-plugin-ggi", ver: "1.1.3-1squeeze3", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "vlc-plugin-jack", ver: "1.1.3-1squeeze3", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "vlc-plugin-notify", ver: "1.1.3-1squeeze3", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "vlc-plugin-pulse", ver: "1.1.3-1squeeze3", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "vlc-plugin-sdl", ver: "1.1.3-1squeeze3", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "vlc-plugin-svg", ver: "1.1.3-1squeeze3", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "vlc-plugin-svgalib", ver: "1.1.3-1squeeze3", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "vlc-plugin-zvbi", ver: "1.1.3-1squeeze3", rls: "DEB6" ) ) != NULL){
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

