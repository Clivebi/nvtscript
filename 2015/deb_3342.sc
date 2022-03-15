if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.703342" );
	script_version( "$Revision: 14278 $" );
	script_cve_id( "CVE-2015-5949" );
	script_name( "Debian Security Advisory DSA 3342-1 (vlc - security update)" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-18 15:47:26 +0100 (Mon, 18 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2015-08-20 00:00:00 +0200 (Thu, 20 Aug 2015)" );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	script_xref( name: "URL", value: "http://www.debian.org/security/2015/dsa-3342.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2015 Greenbone Networks GmbH http://greenbone.net" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB8" );
	script_tag( name: "affected", value: "vlc on Debian Linux" );
	script_tag( name: "solution", value: "For the stable distribution (jessie), this problem has been fixed in
version 2.2.0~rc2-2+deb8u1.

For the unstable distribution (sid), this problem will be fixed shortly.

We recommend that you upgrade your vlc packages." );
	script_tag( name: "summary", value: "Loren Maggiore of Trail of Bits discovered that the 3GP parser of VLC, a
multimedia player and streamer, could dereference an arbitrary pointer
due to insufficient restrictions on a writable buffer. This could allow
remote attackers to execute arbitrary code via crafted 3GP files." );
	script_tag( name: "vuldetect", value: "This check tests the installed software version using the apt package manager." );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(( res = isdpkgvuln( pkg: "libvlc-dev", ver: "2.2.0~rc2-2+deb8u1", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libvlc5", ver: "2.2.0~rc2-2+deb8u1", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libvlccore-dev", ver: "2.2.0~rc2-2+deb8u1", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libvlccore8", ver: "2.2.0~rc2-2+deb8u1", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "vlc", ver: "2.2.0~rc2-2+deb8u1", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "vlc-data", ver: "2.2.0~rc2-2+deb8u1", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "vlc-dbg", ver: "2.2.0~rc2-2+deb8u1", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "vlc-nox", ver: "2.2.0~rc2-2+deb8u1", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "vlc-plugin-fluidsynth", ver: "2.2.0~rc2-2+deb8u1", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "vlc-plugin-jack", ver: "2.2.0~rc2-2+deb8u1", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "vlc-plugin-notify", ver: "2.2.0~rc2-2+deb8u1", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "vlc-plugin-pulse", ver: "2.2.0~rc2-2+deb8u1", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "vlc-plugin-samba", ver: "2.2.0~rc2-2+deb8u1", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "vlc-plugin-sdl", ver: "2.2.0~rc2-2+deb8u1", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "vlc-plugin-svg", ver: "2.2.0~rc2-2+deb8u1", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "vlc-plugin-zvbi", ver: "2.2.0~rc2-2+deb8u1", rls: "DEB8" ) ) != NULL){
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

