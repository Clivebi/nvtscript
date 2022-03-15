if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.892126" );
	script_version( "2021-07-23T11:01:09+0000" );
	script_cve_id( "CVE-2016-9811", "CVE-2017-5837", "CVE-2017-5844" );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:N/A:P" );
	script_tag( name: "last_modification", value: "2021-07-23 11:01:09 +0000 (Fri, 23 Jul 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:L/AC:H/PR:N/UI:R/S:U/C:N/I:N/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2018-01-05 02:31:00 +0000 (Fri, 05 Jan 2018)" );
	script_tag( name: "creation_date", value: "2020-02-29 04:00:16 +0000 (Sat, 29 Feb 2020)" );
	script_name( "Debian LTS: Security Advisory for gst-plugins-base0.10 (DLA-2126-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB8" );
	script_xref( name: "URL", value: "https://lists.debian.org/debian-lts-announce/2020/02/msg00032.html" );
	script_xref( name: "URL", value: "https://security-tracker.debian.org/tracker/DLA-2126-1" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'gst-plugins-base0.10'
  package(s) announced via the DLA-2126-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "Some isses have been found in gst-plugins-base0.10, a package that
provides GStreamer plugins from the 'base' set.
All issues are related to crafted ico-files that could result in an
out-of-bounds read or crafted video- and ASDF-files that could produce
floating point exceptions, which could cause a denial of service." );
	script_tag( name: "affected", value: "'gst-plugins-base0.10' package(s) on Debian Linux." );
	script_tag( name: "solution", value: "For Debian 8 'Jessie', these problems have been fixed in version
0.10.36-2+deb8u2.

We recommend that you upgrade your gst-plugins-base0.10 packages." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(!isnull( res = isdpkgvuln( pkg: "gir1.2-gst-plugins-base-0.10", ver: "0.10.36-2+deb8u2", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "gstreamer0.10-alsa", ver: "0.10.36-2+deb8u2", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "gstreamer0.10-gnomevfs", ver: "0.10.36-2+deb8u2", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "gstreamer0.10-plugins-base", ver: "0.10.36-2+deb8u2", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "gstreamer0.10-plugins-base-apps", ver: "0.10.36-2+deb8u2", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "gstreamer0.10-plugins-base-dbg", ver: "0.10.36-2+deb8u2", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "gstreamer0.10-plugins-base-doc", ver: "0.10.36-2+deb8u2", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "gstreamer0.10-x", ver: "0.10.36-2+deb8u2", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libgstreamer-plugins-base0.10-0", ver: "0.10.36-2+deb8u2", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libgstreamer-plugins-base0.10-dev", ver: "0.10.36-2+deb8u2", rls: "DEB8" ) )){
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

