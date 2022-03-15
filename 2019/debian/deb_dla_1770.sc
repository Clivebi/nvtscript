if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.891770" );
	script_version( "2021-09-03T08:01:30+0000" );
	script_cve_id( "CVE-2019-9928" );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2021-09-03 08:01:30 +0000 (Fri, 03 Sep 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-08-24 17:37:00 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2019-04-29 02:00:08 +0000 (Mon, 29 Apr 2019)" );
	script_name( "Debian LTS: Security Advisory for gst-plugins-base1.0 (DLA-1770-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2019 Greenbone Networks GmbH" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB8" );
	script_xref( name: "URL", value: "https://lists.debian.org/debian-lts-announce/2019/04/msg00031.html" );
	script_xref( name: "URL", value: "https://security-tracker.debian.org/tracker/DLA-1770-1" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'gst-plugins-base1.0'
  package(s) announced via the DLA-1770-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "The RTSP connection parser in the base GStreamer packages version 1.0,
which is a streaming media framework, was vulnerable against an
heap-based buffer overflow by sending a longer than allowed session id in
a response and including a semicolon to change the maximum length. This
could result in a remote code execution." );
	script_tag( name: "affected", value: "'gst-plugins-base1.0' package(s) on Debian Linux." );
	script_tag( name: "solution", value: "For Debian 8 'Jessie', this problem has been fixed in version
1.4.4-2+deb8u2.

We recommend that you upgrade your gst-plugins-base1.0 packages." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(!isnull( res = isdpkgvuln( pkg: "gir1.2-gst-plugins-base-1.0", ver: "1.4.4-2+deb8u2", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "gstreamer1.0-alsa", ver: "1.4.4-2+deb8u2", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "gstreamer1.0-plugins-base", ver: "1.4.4-2+deb8u2", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "gstreamer1.0-plugins-base-apps", ver: "1.4.4-2+deb8u2", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "gstreamer1.0-plugins-base-dbg", ver: "1.4.4-2+deb8u2", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "gstreamer1.0-plugins-base-doc", ver: "1.4.4-2+deb8u2", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "gstreamer1.0-x", ver: "1.4.4-2+deb8u2", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libgstreamer-plugins-base1.0-0", ver: "1.4.4-2+deb8u2", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libgstreamer-plugins-base1.0-dev", ver: "1.4.4-2+deb8u2", rls: "DEB8" ) )){
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
exit( 0 );

