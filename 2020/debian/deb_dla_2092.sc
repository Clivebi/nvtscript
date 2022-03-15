if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.892092" );
	script_version( "2021-07-27T11:00:54+0000" );
	script_cve_id( "CVE-2020-0569" );
	script_tag( name: "cvss_base", value: "2.7" );
	script_tag( name: "cvss_base_vector", value: "AV:A/AC:L/Au:S/C:N/I:N/A:P" );
	script_tag( name: "last_modification", value: "2021-07-27 11:00:54 +0000 (Tue, 27 Jul 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:A/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-12-03 14:43:00 +0000 (Thu, 03 Dec 2020)" );
	script_tag( name: "creation_date", value: "2020-02-01 04:00:08 +0000 (Sat, 01 Feb 2020)" );
	script_name( "Debian LTS: Security Advisory for qtbase-opensource-src (DLA-2092-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB8" );
	script_xref( name: "URL", value: "https://lists.debian.org/debian-lts-announce/2020/02/msg00000.html" );
	script_xref( name: "URL", value: "https://security-tracker.debian.org/tracker/DLA-2092-1" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'qtbase-opensource-src'
  package(s) announced via the DLA-2092-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "In Qt5's plugin loader code as found in qtbase-opensource-src, it was
possible to (side-)load plugins from 'the' local folder in addition to a
system-widely defined library path." );
	script_tag( name: "affected", value: "'qtbase-opensource-src' package(s) on Debian Linux." );
	script_tag( name: "solution", value: "For Debian 8 'Jessie', this problem has been fixed in version
5.3.2+dfsg-4+deb8u4.

We recommend that you upgrade your qtbase-opensource-src packages." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(!isnull( res = isdpkgvuln( pkg: "libqt5concurrent5", ver: "5.3.2+dfsg-4+deb8u4", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libqt5core5a", ver: "5.3.2+dfsg-4+deb8u4", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libqt5dbus5", ver: "5.3.2+dfsg-4+deb8u4", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libqt5gui5", ver: "5.3.2+dfsg-4+deb8u4", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libqt5network5", ver: "5.3.2+dfsg-4+deb8u4", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libqt5opengl5", ver: "5.3.2+dfsg-4+deb8u4", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libqt5opengl5-dev", ver: "5.3.2+dfsg-4+deb8u4", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libqt5printsupport5", ver: "5.3.2+dfsg-4+deb8u4", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libqt5sql5", ver: "5.3.2+dfsg-4+deb8u4", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libqt5sql5-mysql", ver: "5.3.2+dfsg-4+deb8u4", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libqt5sql5-odbc", ver: "5.3.2+dfsg-4+deb8u4", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libqt5sql5-psql", ver: "5.3.2+dfsg-4+deb8u4", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libqt5sql5-sqlite", ver: "5.3.2+dfsg-4+deb8u4", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libqt5sql5-tds", ver: "5.3.2+dfsg-4+deb8u4", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libqt5test5", ver: "5.3.2+dfsg-4+deb8u4", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libqt5widgets5", ver: "5.3.2+dfsg-4+deb8u4", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libqt5xml5", ver: "5.3.2+dfsg-4+deb8u4", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "qt5-default", ver: "5.3.2+dfsg-4+deb8u4", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "qt5-qmake", ver: "5.3.2+dfsg-4+deb8u4", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "qtbase5-dbg", ver: "5.3.2+dfsg-4+deb8u4", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "qtbase5-dev", ver: "5.3.2+dfsg-4+deb8u4", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "qtbase5-dev-tools", ver: "5.3.2+dfsg-4+deb8u4", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "qtbase5-dev-tools-dbg", ver: "5.3.2+dfsg-4+deb8u4", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "qtbase5-doc-html", ver: "5.3.2+dfsg-4+deb8u4", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "qtbase5-examples", ver: "5.3.2+dfsg-4+deb8u4", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "qtbase5-examples-dbg", ver: "5.3.2+dfsg-4+deb8u4", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "qtbase5-private-dev", ver: "5.3.2+dfsg-4+deb8u4", rls: "DEB8" ) )){
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

