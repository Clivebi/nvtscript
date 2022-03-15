if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.892640" );
	script_version( "2021-08-25T09:01:10+0000" );
	script_cve_id( "CVE-2021-3497" );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2021-08-25 09:01:10 +0000 (Wed, 25 Aug 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-04-27 16:48:00 +0000 (Tue, 27 Apr 2021)" );
	script_tag( name: "creation_date", value: "2021-04-27 03:00:05 +0000 (Tue, 27 Apr 2021)" );
	script_name( "Debian LTS: Security Advisory for gst-plugins-good1.0 (DLA-2640-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB9" );
	script_xref( name: "URL", value: "https://lists.debian.org/debian-lts-announce/2021/04/msg00027.html" );
	script_xref( name: "URL", value: "https://security-tracker.debian.org/tracker/DLA-2640-1" );
	script_xref( name: "Advisory-ID", value: "DLA-2640-1" );
	script_xref( name: "URL", value: "https://bugs.debian.org/986910" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'gst-plugins-good1.0'
  package(s) announced via the DLA-2640-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "A use-after-free vulnerability was found in the Matroska plugin of
the GStreamer media framework, which may result in denial of service or
potentially the execution of arbitrary code if a malformed media file
is opened." );
	script_tag( name: "affected", value: "'gst-plugins-good1.0' package(s) on Debian Linux." );
	script_tag( name: "solution", value: "For Debian 9 stretch, this problem has been fixed in version
1.10.4-1+deb9u1.

We recommend that you upgrade your gst-plugins-good1.0 packages." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(!isnull( res = isdpkgvuln( pkg: "gstreamer1.0-plugins-good", ver: "1.10.4-1+deb9u1", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "gstreamer1.0-plugins-good-dbg", ver: "1.10.4-1+deb9u1", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "gstreamer1.0-plugins-good-doc", ver: "1.10.4-1+deb9u1", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "gstreamer1.0-pulseaudio", ver: "1.10.4-1+deb9u1", rls: "DEB9" ) )){
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

