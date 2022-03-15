if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.703820" );
	script_version( "2021-09-08T11:01:32+0000" );
	script_cve_id( "CVE-2016-10198", "CVE-2016-10199", "CVE-2017-5840", "CVE-2017-5841", "CVE-2017-5845" );
	script_name( "Debian Security Advisory DSA 3820-1 (gst-plugins-good1.0 - security update)" );
	script_tag( name: "last_modification", value: "2021-09-08 11:01:32 +0000 (Wed, 08 Sep 2021)" );
	script_tag( name: "creation_date", value: "2017-03-27 00:00:00 +0200 (Mon, 27 Mar 2017)" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2018-01-05 02:30:00 +0000 (Fri, 05 Jan 2018)" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	script_xref( name: "URL", value: "http://www.debian.org/security/2017/dsa-3820.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2017 Greenbone Networks GmbH" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB(8|9)" );
	script_tag( name: "affected", value: "gst-plugins-good1.0 on Debian Linux" );
	script_tag( name: "solution", value: "For the stable distribution (jessie), these problems have been fixed in
version 1.4.4-2+deb8u3.

For the upcoming stable distribution (stretch), these problems have been
fixed in version 1.10.3-1.

For the unstable distribution (sid), these problems have been fixed in
version 1.10.3-1.

We recommend that you upgrade your gst-plugins-good1.0 packages." );
	script_tag( name: "summary", value: "Hanno Boeck discovered multiple vulnerabilities in the GStreamer media
framework and its codecs and demuxers, which may result in denial of
service or the execution of arbitrary code if a malformed media file is
opened." );
	script_tag( name: "vuldetect", value: "This check tests the installed software version using the apt package manager." );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(( res = isdpkgvuln( pkg: "gstreamer1.0-plugins-good:i386", ver: "1.4.4-2+deb8u3", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "gstreamer1.0-plugins-good:amd64", ver: "1.4.4-2+deb8u3", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "gstreamer1.0-plugins-good-dbg:i386", ver: "1.4.4-2+deb8u3", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "gstreamer1.0-plugins-good-dbg:amd64", ver: "1.4.4-2+deb8u3", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "gstreamer1.0-plugins-good-doc", ver: "1.4.4-2+deb8u3", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "gstreamer1.0-pulseaudio:i386", ver: "1.4.4-2+deb8u3", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "gstreamer1.0-pulseaudio:amd64", ver: "1.4.4-2+deb8u3", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "gstreamer1.0-plugins-good:i386", ver: "1.10.3-1", rls: "DEB9" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "gstreamer1.0-plugins-good:amd64", ver: "1.10.3-1", rls: "DEB9" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "gstreamer1.0-plugins-good-dbg:i386", ver: "1.10.3-1", rls: "DEB9" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "gstreamer1.0-plugins-good-dbg:amd64", ver: "1.10.3-1", rls: "DEB9" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "gstreamer1.0-plugins-good-doc", ver: "1.10.3-1", rls: "DEB9" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "gstreamer1.0-pulseaudio:i386", ver: "1.10.3-1", rls: "DEB9" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "gstreamer1.0-pulseaudio:amd64", ver: "1.10.3-1", rls: "DEB9" ) ) != NULL){
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

