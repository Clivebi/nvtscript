if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.704374" );
	script_version( "2021-09-03T08:01:30+0000" );
	script_cve_id( "CVE-2018-15518", "CVE-2018-19870", "CVE-2018-19873" );
	script_name( "Debian Security Advisory DSA 4374-1 (qtbase-opensource-src - security update)" );
	script_tag( name: "last_modification", value: "2021-09-03 08:01:30 +0000 (Fri, 03 Sep 2021)" );
	script_tag( name: "creation_date", value: "2019-01-28 00:00:00 +0100 (Mon, 28 Jan 2019)" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-09-28 09:15:00 +0000 (Mon, 28 Sep 2020)" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	script_xref( name: "URL", value: "https://www.debian.org/security/2019/dsa-4374.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2019 Greenbone Networks GmbH" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB9" );
	script_tag( name: "affected", value: "qtbase-opensource-src on Debian Linux" );
	script_tag( name: "solution", value: "For the stable distribution (stretch), these problems have been fixed in
version 5.7.1+dfsg-3+deb9u1.

We recommend that you upgrade your qtbase-opensource-src packages." );
	script_xref( name: "URL", value: "https://security-tracker.debian.org/tracker/qtbase-opensource-src" );
	script_tag( name: "summary", value: "Several issues were discovered in qtbase-opensource-src, a
cross-platform C++ application framework, which could lead to
denial-of-service via application crash. Additionally, this update
fixes a problem affecting vlc, where it would start without a GUI." );
	script_tag( name: "vuldetect", value: "This check tests the installed software version using the apt package manager." );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(!isnull( res = isdpkgvuln( pkg: "libqt5concurrent5", ver: "5.7.1+dfsg-3+deb9u1", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libqt5core5a", ver: "5.7.1+dfsg-3+deb9u1", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libqt5dbus5", ver: "5.7.1+dfsg-3+deb9u1", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libqt5gui5", ver: "5.7.1+dfsg-3+deb9u1", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libqt5network5", ver: "5.7.1+dfsg-3+deb9u1", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libqt5opengl5", ver: "5.7.1+dfsg-3+deb9u1", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libqt5opengl5-dev", ver: "5.7.1+dfsg-3+deb9u1", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libqt5printsupport5", ver: "5.7.1+dfsg-3+deb9u1", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libqt5sql5", ver: "5.7.1+dfsg-3+deb9u1", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libqt5sql5-ibase", ver: "5.7.1+dfsg-3+deb9u1", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libqt5sql5-mysql", ver: "5.7.1+dfsg-3+deb9u1", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libqt5sql5-odbc", ver: "5.7.1+dfsg-3+deb9u1", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libqt5sql5-psql", ver: "5.7.1+dfsg-3+deb9u1", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libqt5sql5-sqlite", ver: "5.7.1+dfsg-3+deb9u1", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libqt5sql5-tds", ver: "5.7.1+dfsg-3+deb9u1", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libqt5test5", ver: "5.7.1+dfsg-3+deb9u1", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libqt5widgets5", ver: "5.7.1+dfsg-3+deb9u1", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libqt5xml5", ver: "5.7.1+dfsg-3+deb9u1", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "qt5-default", ver: "5.7.1+dfsg-3+deb9u1", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "qt5-gtk-platformtheme", ver: "5.7.1+dfsg-3+deb9u1", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "qt5-qmake", ver: "5.7.1+dfsg-3+deb9u1", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "qtbase5-dev", ver: "5.7.1+dfsg-3+deb9u1", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "qtbase5-dev-tools", ver: "5.7.1+dfsg-3+deb9u1", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "qtbase5-doc", ver: "5.7.1+dfsg-3+deb9u1", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "qtbase5-doc-html", ver: "5.7.1+dfsg-3+deb9u1", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "qtbase5-examples", ver: "5.7.1+dfsg-3+deb9u1", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "qtbase5-private-dev", ver: "5.7.1+dfsg-3+deb9u1", rls: "DEB9" ) )){
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

