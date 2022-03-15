if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.703150" );
	script_version( "2021-09-20T13:38:59+0000" );
	script_cve_id( "CVE-2014-9626", "CVE-2014-9627", "CVE-2014-9628", "CVE-2014-9629", "CVE-2014-9630" );
	script_name( "Debian Security Advisory DSA 3150-1 (vlc - security update)" );
	script_tag( name: "last_modification", value: "2021-09-20 13:38:59 +0000 (Mon, 20 Sep 2021)" );
	script_tag( name: "creation_date", value: "2015-02-02 00:00:00 +0100 (Mon, 02 Feb 2015)" );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "URL", value: "http://www.debian.org/security/2015/dsa-3150.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2015 Greenbone Networks GmbH" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB7" );
	script_tag( name: "affected", value: "vlc on Debian Linux" );
	script_tag( name: "solution", value: "For the stable distribution (wheezy),
these problems have been fixed in version 2.0.3-5+deb7u2.

For the upcoming stable distribution (jessie), these problems have been
fixed in version 2.2.0~rc2-2.

For the unstable distribution (sid), these problems have been fixed in
version 2.2.0~rc2-2.

We recommend that you upgrade your vlc packages." );
	script_tag( name: "summary", value: "Fabian Yamaguchi discovered multiple
vulnerabilities in VLC, a multimedia player and streamer:

CVE-2014-9626
The MP4 demuxer, when parsing string boxes, did not properly check
the length of the box, leading to a possible integer underflow when
using this length value in a call to memcpy(). This could allow
remote attackers to cause a denial of service (crash) or arbitrary
code execution via crafted MP4 files.

CVE-2014-9627
The MP4 demuxer, when parsing string boxes, did not properly check
that the conversion of the box length from 64bit integer to 32bit
integer on 32bit platforms did not cause a truncation, leading to
a possible buffer overflow. This could allow remote attackers to
cause a denial of service (crash) or arbitrary code execution via
crafted MP4 files.

CVE-2014-9628
The MP4 demuxer, when parsing string boxes, did not properly check
the length of the box, leading to a possible buffer overflow. This
could allow remote attackers to cause a denial of service (crash)
or arbitrary code execution via crafted MP4 files.

CVE-2014-9629
The Dirac and Schroedinger encoders did not properly check for an
integer overflow on 32bit platforms, leading to a possible buffer
overflow. This could allow remote attackers to cause a denial of
service (crash) or arbitrary code execution." );
	script_tag( name: "vuldetect", value: "This check tests the installed
software version using the apt package manager." );
	script_tag( name: "qod_type", value: "package" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(( res = isdpkgvuln( pkg: "libvlc-dev", ver: "2.0.3-5+deb7u2", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libvlc5", ver: "2.0.3-5+deb7u2", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libvlccore-dev", ver: "2.0.3-5+deb7u2", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libvlccore5", ver: "2.0.3-5+deb7u2", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "vlc", ver: "2.0.3-5+deb7u2", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "vlc-data", ver: "2.0.3-5+deb7u2", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "vlc-dbg", ver: "2.0.3-5+deb7u2", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "vlc-nox", ver: "2.0.3-5+deb7u2", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "vlc-plugin-fluidsynth", ver: "2.0.3-5+deb7u2", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "vlc-plugin-jack", ver: "2.0.3-5+deb7u2", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "vlc-plugin-notify", ver: "2.0.3-5+deb7u2", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "vlc-plugin-pulse", ver: "2.0.3-5+deb7u2", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "vlc-plugin-sdl", ver: "2.0.3-5+deb7u2", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "vlc-plugin-svg", ver: "2.0.3-5+deb7u2", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "vlc-plugin-zvbi", ver: "2.0.3-5+deb7u2", rls: "DEB7" ) ) != NULL){
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

