if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.703225" );
	script_version( "$Revision: 14275 $" );
	script_cve_id( "CVE-2015-0797" );
	script_name( "Debian Security Advisory DSA 3225-1 (gst-plugins-bad0.10 - security update)" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-18 15:39:45 +0100 (Mon, 18 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2015-04-15 00:00:00 +0200 (Wed, 15 Apr 2015)" );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	script_xref( name: "URL", value: "http://www.debian.org/security/2015/dsa-3225.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2015 Greenbone Networks GmbH http://greenbone.net" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB7" );
	script_tag( name: "affected", value: "gst-plugins-bad0.10 on Debian Linux" );
	script_tag( name: "solution", value: "For the stable distribution (wheezy), this problem has been fixed in
version 0.10.23-7.1+deb7u2.

For the unstable distribution (sid), this problem will be fixed soon.

We recommend that you upgrade your gst-plugins-bad0.10 packages." );
	script_tag( name: "summary", value: "Aki Helin discovered a buffer overflow in the GStreamer plugin for MP4
playback, which could lead to the execution of arbitrary code." );
	script_tag( name: "vuldetect", value: "This check tests the installed software version using the apt package manager." );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(( res = isdpkgvuln( pkg: "gstreamer0.10-plugins-bad", ver: "0.10.23-7.1+deb7u2", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "gstreamer0.10-plugins-bad-dbg", ver: "0.10.23-7.1+deb7u2", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "gstreamer0.10-plugins-bad-doc", ver: "0.10.23-7.1+deb7u2", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libgstreamer-plugins-bad0.10-0", ver: "0.10.23-7.1+deb7u2", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libgstreamer-plugins-bad0.10-dev", ver: "0.10.23-7.1+deb7u2", rls: "DEB7" ) ) != NULL){
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

