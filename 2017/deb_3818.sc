if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.703818" );
	script_version( "2021-09-08T13:01:42+0000" );
	script_cve_id( "CVE-2016-9809", "CVE-2016-9812", "CVE-2016-9813", "CVE-2017-5843", "CVE-2017-5848" );
	script_name( "Debian Security Advisory DSA 3818-1 (gst-plugins-bad1.0 - security update)" );
	script_tag( name: "last_modification", value: "2021-09-08 13:01:42 +0000 (Wed, 08 Sep 2021)" );
	script_tag( name: "creation_date", value: "2017-03-27 00:00:00 +0200 (Mon, 27 Mar 2017)" );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2018-01-05 02:31:00 +0000 (Fri, 05 Jan 2018)" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	script_xref( name: "URL", value: "http://www.debian.org/security/2017/dsa-3818.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2017 Greenbone Networks GmbH" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB(9|8)" );
	script_tag( name: "affected", value: "gst-plugins-bad1.0 on Debian Linux" );
	script_tag( name: "solution", value: "For the stable distribution (jessie), these problems have been fixed in
version 1.4.4-2.1+deb8u2.

For the upcoming stable distribution (stretch), these problems have been
fixed in version 1.10.4-1.

For the unstable distribution (sid), these problems have been fixed in
version 1.10.4-1.

We recommend that you upgrade your gst-plugins-bad1.0 packages." );
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
if(( res = isdpkgvuln( pkg: "gir1.2-gst-plugins-bad-1.0", ver: "1.10.4-1", rls: "DEB9" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "gstreamer1.0-plugins-bad:amd64", ver: "1.10.4-1", rls: "DEB9" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "gstreamer1.0-plugins-bad:i386", ver: "1.10.4-1", rls: "DEB9" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "gstreamer1.0-plugins-bad-dbg:amd64", ver: "1.10.4-1", rls: "DEB9" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "gstreamer1.0-plugins-bad-dbg:i386", ver: "1.10.4-1", rls: "DEB9" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "gstreamer1.0-plugins-bad-doc", ver: "1.10.4-1", rls: "DEB9" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libgstreamer-plugins-bad1.0-0:amd64", ver: "1.10.4-1", rls: "DEB9" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libgstreamer-plugins-bad1.0-0:i386", ver: "1.10.4-1", rls: "DEB9" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libgstreamer-plugins-bad1.0-dev", ver: "1.10.4-1", rls: "DEB9" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "gstreamer1.0-plugins-bad:amd64", ver: "1.4.4-2.1+deb8u2", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "gstreamer1.0-plugins-bad:i386", ver: "1.4.4-2.1+deb8u2", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "gstreamer1.0-plugins-bad-dbg:amd64", ver: "1.4.4-2.1+deb8u2", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "gstreamer1.0-plugins-bad-dbg:i386", ver: "1.4.4-2.1+deb8u2", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "gstreamer1.0-plugins-bad-doc", ver: "1.4.4-2.1+deb8u2", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libgstreamer-plugins-bad1.0-0:i386", ver: "1.4.4-2.1+deb8u2", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libgstreamer-plugins-bad1.0-0:amd64", ver: "1.4.4-2.1+deb8u2", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libgstreamer-plugins-bad1.0-dev", ver: "1.4.4-2.1+deb8u2", rls: "DEB8" ) ) != NULL){
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

