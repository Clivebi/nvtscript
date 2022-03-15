if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.891769" );
	script_version( "2021-09-03T13:01:29+0000" );
	script_cve_id( "CVE-2019-9928" );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2021-09-03 13:01:29 +0000 (Fri, 03 Sep 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-08-24 17:37:00 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2019-04-29 02:00:08 +0000 (Mon, 29 Apr 2019)" );
	script_name( "Debian LTS: Security Advisory for gst-plugins-base0.10 (DLA-1769-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2019 Greenbone Networks GmbH" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB8" );
	script_xref( name: "URL", value: "https://lists.debian.org/debian-lts-announce/2019/04/msg00030.html" );
	script_xref( name: "URL", value: "https://security-tracker.debian.org/tracker/DLA-1769-1" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'gst-plugins-base0.10'
  package(s) announced via the DLA-1769-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "The RTSP connection parser in the base GStreamer packages version 0.10,
which is a streaming media framework, was vulnerable against an
heap-based buffer overflow by sending a longer than allowed session id in
a response and including a semicolon to change the maximum length. This
could result in a remote code execution." );
	script_tag( name: "affected", value: "'gst-plugins-base0.10' package(s) on Debian Linux." );
	script_tag( name: "solution", value: "For Debian 8 'Jessie', this problem has been fixed in version
0.10.36-2+deb8u1.

We recommend that you upgrade your gst-plugins-base0.10 packages." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(!isnull( res = isdpkgvuln( pkg: "gir1.2-gst-plugins-base-0.10", ver: "0.10.36-2+deb8u1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "gstreamer0.10-alsa", ver: "0.10.36-2+deb8u1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "gstreamer0.10-gnomevfs", ver: "0.10.36-2+deb8u1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "gstreamer0.10-plugins-base", ver: "0.10.36-2+deb8u1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "gstreamer0.10-plugins-base-apps", ver: "0.10.36-2+deb8u1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "gstreamer0.10-plugins-base-dbg", ver: "0.10.36-2+deb8u1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "gstreamer0.10-plugins-base-doc", ver: "0.10.36-2+deb8u1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "gstreamer0.10-x", ver: "0.10.36-2+deb8u1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libgstreamer-plugins-base0.10-0", ver: "0.10.36-2+deb8u1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libgstreamer-plugins-base0.10-dev", ver: "0.10.36-2+deb8u1", rls: "DEB8" ) )){
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

