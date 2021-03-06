if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.703724" );
	script_version( "$Revision: 14275 $" );
	script_cve_id( "CVE-2016-9634", "CVE-2016-9635", "CVE-2016-9636" );
	script_name( "Debian Security Advisory DSA 3724-1 (gst-plugins-good0.10 - security update)" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-18 15:39:45 +0100 (Mon, 18 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2016-11-24 00:00:00 +0100 (Thu, 24 Nov 2016)" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	script_xref( name: "URL", value: "http://www.debian.org/security/2016/dsa-3724.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2016 Greenbone Networks GmbH http://greenbone.net" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB8" );
	script_tag( name: "affected", value: "gst-plugins-good0.10 on Debian Linux" );
	script_tag( name: "solution", value: "For the stable distribution (jessie),
these problems have been fixed in version 0.10.31-3+nmu4+deb8u2.

We recommend that you upgrade your gst-plugins-good0.10 packages." );
	script_tag( name: "summary", value: "Chris Evans discovered that the
GStreamer 0.10 plugin used to decode files in the FLIC format allowed execution
of arbitrary code.

This update removes the insecure FLIC file format plugin." );
	script_tag( name: "vuldetect", value: "This check tests the installed software
version using the apt package manager." );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(( res = isdpkgvuln( pkg: "gstreamer0.10-gconf:amd64", ver: "0.10.31-3+nmu4+deb8u2", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "gstreamer0.10-gconf:i386", ver: "0.10.31-3+nmu4+deb8u2", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "gstreamer0.10-plugins-good:amd64", ver: "0.10.31-3+nmu4+deb8u2", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "gstreamer0.10-plugins-good:i386", ver: "0.10.31-3+nmu4+deb8u2", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "gstreamer0.10-plugins-good-dbg:amd64", ver: "0.10.31-3+nmu4+deb8u2", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "gstreamer0.10-plugins-good-dbg:i386", ver: "0.10.31-3+nmu4+deb8u2", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "gstreamer0.10-plugins-good-doc", ver: "0.10.31-3+nmu4+deb8u2", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "gstreamer0.10-pulseaudio:amd64", ver: "0.10.31-3+nmu4+deb8u2", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "gstreamer0.10-pulseaudio:i386", ver: "0.10.31-3+nmu4+deb8u2", rls: "DEB8" ) ) != NULL){
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

