if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.891752" );
	script_version( "2021-09-03T10:01:28+0000" );
	script_cve_id( "CVE-2019-9631" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2021-09-03 10:01:28 +0000 (Fri, 03 Sep 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-07-23 12:15:00 +0000 (Thu, 23 Jul 2020)" );
	script_tag( name: "creation_date", value: "2019-04-09 02:00:09 +0000 (Tue, 09 Apr 2019)" );
	script_name( "Debian LTS: Security Advisory for poppler (DLA-1752-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2019 Greenbone Networks GmbH" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB8" );
	script_xref( name: "URL", value: "https://lists.debian.org/debian-lts-announce/2019/04/msg00011.html" );
	script_xref( name: "URL", value: "https://security-tracker.debian.org/tracker/DLA-1752-1" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'poppler'
  package(s) announced via the DLA-1752-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "A security issue was discovered in the poppler PDF rendering shared
library.

The Poppler shared library had a heap-based buffer over-read in the
CairoRescaleBox.cc downsample_row_box_filter function." );
	script_tag( name: "affected", value: "'poppler' package(s) on Debian Linux." );
	script_tag( name: "solution", value: "For Debian 8 'Jessie', this problem has been fixed in version
0.26.5-2+deb8u9.

We recommend that you upgrade your poppler packages." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(!isnull( res = isdpkgvuln( pkg: "gir1.2-poppler-0.18", ver: "0.26.5-2+deb8u9", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libpoppler-cpp-dev", ver: "0.26.5-2+deb8u9", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libpoppler-cpp0", ver: "0.26.5-2+deb8u9", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libpoppler-dev", ver: "0.26.5-2+deb8u9", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libpoppler-glib-dev", ver: "0.26.5-2+deb8u9", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libpoppler-glib-doc", ver: "0.26.5-2+deb8u9", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libpoppler-glib8", ver: "0.26.5-2+deb8u9", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libpoppler-private-dev", ver: "0.26.5-2+deb8u9", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libpoppler-qt4-4", ver: "0.26.5-2+deb8u9", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libpoppler-qt4-dev", ver: "0.26.5-2+deb8u9", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libpoppler-qt5-1", ver: "0.26.5-2+deb8u9", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libpoppler-qt5-dev", ver: "0.26.5-2+deb8u9", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libpoppler46", ver: "0.26.5-2+deb8u9", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "poppler-dbg", ver: "0.26.5-2+deb8u9", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "poppler-utils", ver: "0.26.5-2+deb8u9", rls: "DEB8" ) )){
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

