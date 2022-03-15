if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.891482" );
	script_version( "2021-06-18T02:00:26+0000" );
	script_cve_id( "CVE-2018-14598", "CVE-2018-14599", "CVE-2018-14600" );
	script_name( "Debian LTS: Security Advisory for libx11 (DLA-1482-1)" );
	script_tag( name: "last_modification", value: "2021-06-18 02:00:26 +0000 (Fri, 18 Jun 2021)" );
	script_tag( name: "creation_date", value: "2018-09-03 00:00:00 +0200 (Mon, 03 Sep 2018)" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-08-24 17:37:00 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	script_xref( name: "URL", value: "https://lists.debian.org/debian-lts-announce/2018/08/msg00030.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH http://greenbone.net" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB8" );
	script_tag( name: "affected", value: "libx11 on Debian Linux" );
	script_tag( name: "solution", value: "For Debian 8 'Jessie', these problems have been fixed in version
2:1.6.2-3+deb8u2.

We recommend that you upgrade your libx11 packages." );
	script_tag( name: "summary", value: "Several issues were discovered in libx11, the client interface to the
X Windows System. The functions XGetFontPath, XListExtensions, and
XListFonts are vulnerable to an off-by-one override on malicious
server responses. A malicious server could also send a reply in which
the first string overflows, causing a variable set to NULL that will
be freed later on, leading to a segmentation fault and Denial of
Service. The function XListExtensions in ListExt.c interprets a
variable as signed instead of unsigned, resulting in an out-of-bounds
write (of up to 128 bytes), leading to a Denial of Service or possibly
remote code execution." );
	script_tag( name: "vuldetect", value: "This check tests the installed software version using the apt package manager." );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(!isnull( res = isdpkgvuln( pkg: "libx11-6", ver: "2:1.6.2-3+deb8u2", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libx11-6-dbg", ver: "2:1.6.2-3+deb8u2", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libx11-data", ver: "2:1.6.2-3+deb8u2", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libx11-dev", ver: "2:1.6.2-3+deb8u2", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libx11-doc", ver: "2:1.6.2-3+deb8u2", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libx11-xcb-dev", ver: "2:1.6.2-3+deb8u2", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libx11-xcb1", ver: "2:1.6.2-3+deb8u2", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libx11-xcb1-dbg", ver: "2:1.6.2-3+deb8u2", rls: "DEB8" ) )){
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

