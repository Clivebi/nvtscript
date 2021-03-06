if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.702973" );
	script_version( "$Revision: 14302 $" );
	script_cve_id( "CVE-2013-1868", "CVE-2013-1954", "CVE-2013-4388" );
	script_name( "Debian Security Advisory DSA 2973-1 (vlc - security update)" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-19 09:28:48 +0100 (Tue, 19 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2014-07-07 00:00:00 +0200 (Mon, 07 Jul 2014)" );
	script_tag( name: "cvss_base", value: "9.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:C/I:C/A:C" );
	script_xref( name: "URL", value: "http://www.debian.org/security/2014/dsa-2973.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2014 Greenbone Networks GmbH http://greenbone.net" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB7" );
	script_tag( name: "affected", value: "vlc on Debian Linux" );
	script_tag( name: "solution", value: "For the stable distribution (wheezy), these problems have been fixed in
version 2.0.3-5+deb7u1.

For the testing distribution (jessie), these problems have been fixed in
version 2.1.0-1.

For the unstable distribution (sid), these problems have been fixed in
version 2.1.0-1.

We recommend that you upgrade your vlc packages." );
	script_tag( name: "summary", value: "Multiple buffer overflows have been found in the VideoLAN media player.
Processing malformed subtitles or movie files could lead to denial of
service and potentially the execution of arbitrary code." );
	script_tag( name: "vuldetect", value: "This check tests the installed software version using the apt package manager." );
	script_tag( name: "qod_type", value: "package" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(( res = isdpkgvuln( pkg: "libvlc-dev", ver: "2.0.3-5+deb7u1", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libvlc5", ver: "2.0.3-5+deb7u1", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libvlccore-dev", ver: "2.0.3-5+deb7u1", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libvlccore5", ver: "2.0.3-5+deb7u1", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "vlc", ver: "2.0.3-5+deb7u1", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "vlc-data", ver: "2.0.3-5+deb7u1", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "vlc-dbg", ver: "2.0.3-5+deb7u1", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "vlc-nox", ver: "2.0.3-5+deb7u1", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "vlc-plugin-fluidsynth", ver: "2.0.3-5+deb7u1", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "vlc-plugin-jack", ver: "2.0.3-5+deb7u1", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "vlc-plugin-notify", ver: "2.0.3-5+deb7u1", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "vlc-plugin-pulse", ver: "2.0.3-5+deb7u1", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "vlc-plugin-sdl", ver: "2.0.3-5+deb7u1", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "vlc-plugin-svg", ver: "2.0.3-5+deb7u1", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "vlc-plugin-zvbi", ver: "2.0.3-5+deb7u1", rls: "DEB7" ) ) != NULL){
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

