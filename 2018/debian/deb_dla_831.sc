if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.890831" );
	script_version( "2021-06-17T02:00:27+0000" );
	script_cve_id( "CVE-2017-5884", "CVE-2017-5885" );
	script_name( "Debian LTS: Security Advisory for gtk-vnc (DLA-831-1)" );
	script_tag( name: "last_modification", value: "2021-06-17 02:00:27 +0000 (Thu, 17 Jun 2021)" );
	script_tag( name: "creation_date", value: "2018-01-08 00:00:00 +0100 (Mon, 08 Jan 2018)" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2018-01-05 02:31:00 +0000 (Fri, 05 Jan 2018)" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	script_xref( name: "URL", value: "https://lists.debian.org/debian-lts-announce/2017/02/msg00020.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH http://greenbone.net" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB7" );
	script_tag( name: "affected", value: "gtk-vnc on Debian Linux" );
	script_tag( name: "solution", value: "For Debian 7 'Wheezy', these problems have been fixed in version
0.5.0-3.1+deb7u1.

We recommend that you upgrade your gtk-vnc packages." );
	script_tag( name: "summary", value: "Josef Gajdusek discovered two vulnerabilities in gtk-vnc, a VNC viewer
widget for GTK:

CVE-2017-5884

Fix bounds checking for RRE, hextile & copyrec encodings. This bug
allowed a remote server to cause a denial of service by buffer
overflow via a carefully crafted message containing subrectangles
outside the drawing area.

CVE-2017-5885

Correctly validate color map range indexes. This bug allowed a
remote server to cause a denial of service by buffer overflow via
a carefully crafted message with out-of-range colour values." );
	script_tag( name: "vuldetect", value: "This check tests the installed software version using the apt package manager." );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(!isnull( res = isdpkgvuln( pkg: "gir1.2-gtk-vnc-2.0", ver: "0.5.0-3.1+deb7u1", rls: "DEB7" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "gvncviewer", ver: "0.5.0-3.1+deb7u1", rls: "DEB7" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libgtk-vnc-1.0-0", ver: "0.5.0-3.1+deb7u1", rls: "DEB7" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libgtk-vnc-1.0-0-dbg", ver: "0.5.0-3.1+deb7u1", rls: "DEB7" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libgtk-vnc-1.0-dev", ver: "0.5.0-3.1+deb7u1", rls: "DEB7" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libgtk-vnc-2.0-0", ver: "0.5.0-3.1+deb7u1", rls: "DEB7" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libgtk-vnc-2.0-0-dbg", ver: "0.5.0-3.1+deb7u1", rls: "DEB7" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libgtk-vnc-2.0-dev", ver: "0.5.0-3.1+deb7u1", rls: "DEB7" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libgvnc-1.0-0", ver: "0.5.0-3.1+deb7u1", rls: "DEB7" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libgvnc-1.0-0-dbg", ver: "0.5.0-3.1+deb7u1", rls: "DEB7" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libgvnc-1.0-dev", ver: "0.5.0-3.1+deb7u1", rls: "DEB7" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "mozilla-gtk-vnc", ver: "0.5.0-3.1+deb7u1", rls: "DEB7" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "python-gtk-vnc", ver: "0.5.0-3.1+deb7u1", rls: "DEB7" ) )){
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

