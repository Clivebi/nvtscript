if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.892659" );
	script_version( "2021-08-24T14:01:01+0000" );
	script_cve_id( "CVE-2018-10196", "CVE-2020-18032" );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2021-08-24 14:01:01 +0000 (Tue, 24 Aug 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-07-03 06:15:00 +0000 (Sat, 03 Jul 2021)" );
	script_tag( name: "creation_date", value: "2021-05-14 03:03:24 +0000 (Fri, 14 May 2021)" );
	script_name( "Debian LTS: Security Advisory for graphviz (DLA-2659-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB9" );
	script_xref( name: "URL", value: "https://lists.debian.org/debian-lts-announce/2021/05/msg00014.html" );
	script_xref( name: "URL", value: "https://security-tracker.debian.org/tracker/DLA-2659-1" );
	script_xref( name: "Advisory-ID", value: "DLA-2659-1" );
	script_xref( name: "URL", value: "https://bugs.debian.org/898841" );
	script_xref( name: "URL", value: "https://bugs.debian.org/988000" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'graphviz'
  package(s) announced via the DLA-2659-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "CVE-2018-10196

NULL pointer dereference vulnerability in the rebuild_vlists
function in lib/dotgen/conc.c in the dotgen library allows
remote attackers to cause a denial of service (application
crash) via a crafted file.

CVE-2020-18032

A buffer overflow was discovered in Graphviz, which could
potentially result in the execution of arbitrary code when
processing a malformed file." );
	script_tag( name: "affected", value: "'graphviz' package(s) on Debian Linux." );
	script_tag( name: "solution", value: "For Debian 9 stretch, these problems have been fixed in version
2.38.0-17+deb9u1.

We recommend that you upgrade your graphviz packages." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(!isnull( res = isdpkgvuln( pkg: "graphviz", ver: "2.38.0-17+deb9u1", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "graphviz-dev", ver: "2.38.0-17+deb9u1", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "graphviz-doc", ver: "2.38.0-17+deb9u1", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libcdt5", ver: "2.38.0-17+deb9u1", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libcgraph6", ver: "2.38.0-17+deb9u1", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libgraphviz-dev", ver: "2.38.0-17+deb9u1", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libgv-guile", ver: "2.38.0-17+deb9u1", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libgv-lua", ver: "2.38.0-17+deb9u1", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libgv-perl", ver: "2.38.0-17+deb9u1", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libgv-python", ver: "2.38.0-17+deb9u1", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libgv-ruby", ver: "2.38.0-17+deb9u1", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libgv-tcl", ver: "2.38.0-17+deb9u1", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libgvc6", ver: "2.38.0-17+deb9u1", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libgvc6-plugins-gtk", ver: "2.38.0-17+deb9u1", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libgvpr2", ver: "2.38.0-17+deb9u1", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libpathplan4", ver: "2.38.0-17+deb9u1", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libxdot4", ver: "2.38.0-17+deb9u1", rls: "DEB9" ) )){
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

