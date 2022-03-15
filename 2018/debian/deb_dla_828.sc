if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.890828" );
	script_version( "2021-06-16T11:00:23+0000" );
	script_cve_id( "CVE-2016-10198", "CVE-2017-5840" );
	script_name( "Debian LTS: Security Advisory for gst-plugins-good0.10 (DLA-828-1)" );
	script_tag( name: "last_modification", value: "2021-06-16 11:00:23 +0000 (Wed, 16 Jun 2021)" );
	script_tag( name: "creation_date", value: "2018-01-08 00:00:00 +0100 (Mon, 08 Jan 2018)" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-05-30 18:15:00 +0000 (Sat, 30 May 2020)" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	script_xref( name: "URL", value: "https://lists.debian.org/debian-lts-announce/2017/02/msg00017.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH http://greenbone.net" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB7" );
	script_tag( name: "affected", value: "gst-plugins-good0.10 on Debian Linux" );
	script_tag( name: "solution", value: "For Debian 7 'Wheezy', these problems have been fixed in version
0.10.31-3+nmu1+deb7u2.

We recommend that you upgrade your gst-plugins-good0.10 packages." );
	script_tag( name: "summary", value: "Two memory handling issues were found in gst-plugins-good0.10:

CVE-2016-10198

An invalid read can be triggered in the aacparse element via a
maliciously crafted file.

CVE-2017-5840

An out of bounds heap read can be triggered in the qtdemux element
via a maliciously crafted file." );
	script_tag( name: "vuldetect", value: "This check tests the installed software version using the apt package manager." );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(!isnull( res = isdpkgvuln( pkg: "gstreamer0.10-gconf", ver: "0.10.31-3+nmu1+deb7u2", rls: "DEB7" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "gstreamer0.10-plugins-good", ver: "0.10.31-3+nmu1+deb7u2", rls: "DEB7" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "gstreamer0.10-plugins-good-dbg", ver: "0.10.31-3+nmu1+deb7u2", rls: "DEB7" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "gstreamer0.10-plugins-good-doc", ver: "0.10.31-3+nmu1+deb7u2", rls: "DEB7" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "gstreamer0.10-pulseaudio", ver: "0.10.31-3+nmu1+deb7u2", rls: "DEB7" ) )){
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

