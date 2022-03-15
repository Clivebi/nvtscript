if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.892164" );
	script_version( "2020-04-01T03:00:15+0000" );
	script_cve_id( "CVE-2015-0797", "CVE-2016-9809", "CVE-2017-5843", "CVE-2017-5848" );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2020-04-01 03:00:15 +0000 (Wed, 01 Apr 2020)" );
	script_tag( name: "creation_date", value: "2020-04-01 03:00:15 +0000 (Wed, 01 Apr 2020)" );
	script_name( "Debian LTS: Security Advisory for gst-plugins-bad0.10 (DLA-2164-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB8" );
	script_xref( name: "URL", value: "https://lists.debian.org/debian-lts-announce/2020/03/msg00038.html" );
	script_xref( name: "URL", value: "https://security-tracker.debian.org/tracker/DLA-2164-1" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'gst-plugins-bad0.10'
  package(s) announced via the DLA-2164-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "Several issues have been found in gst-plugins-bad0.10, a package
containing GStreamer plugins from the 'bad' set.

All issues are about use-after-free, out of bounds reads or buffer
overflow in different modules." );
	script_tag( name: "affected", value: "'gst-plugins-bad0.10' package(s) on Debian Linux." );
	script_tag( name: "solution", value: "For Debian 8 'Jessie', these problems have been fixed in version
0.10.23-7.4+deb8u3.

We recommend that you upgrade your gst-plugins-bad0.10 packages." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(!isnull( res = isdpkgvuln( pkg: "gstreamer0.10-plugins-bad", ver: "0.10.23-7.4+deb8u3", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "gstreamer0.10-plugins-bad-dbg", ver: "0.10.23-7.4+deb8u3", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "gstreamer0.10-plugins-bad-doc", ver: "0.10.23-7.4+deb8u3", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libgstreamer-plugins-bad0.10-0", ver: "0.10.23-7.4+deb8u3", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libgstreamer-plugins-bad0.10-dev", ver: "0.10.23-7.4+deb8u3", rls: "DEB8" ) )){
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

