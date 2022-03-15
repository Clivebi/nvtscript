if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.892518" );
	script_version( "2021-08-25T06:00:59+0000" );
	script_cve_id( "CVE-2020-35492" );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2021-08-25 06:00:59 +0000 (Wed, 25 Aug 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-05-14 13:44:00 +0000 (Fri, 14 May 2021)" );
	script_tag( name: "creation_date", value: "2021-01-11 13:00:52 +0000 (Mon, 11 Jan 2021)" );
	script_name( "Debian LTS: Security Advisory for cairo (DLA-2518-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB9" );
	script_xref( name: "URL", value: "https://lists.debian.org/debian-lts-announce/2021/01/msg00006.html" );
	script_xref( name: "URL", value: "https://security-tracker.debian.org/tracker/DLA-2518-1" );
	script_xref( name: "URL", value: "https://bugs.debian.org/978658" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'cairo'
  package(s) announced via the DLA-2518-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "LibreOffice slideshow aborts with stack smashing in cairo's
composite_boxes." );
	script_tag( name: "affected", value: "'cairo' package(s) on Debian Linux." );
	script_tag( name: "solution", value: "For Debian 9 stretch, this problem has been fixed in version
1.14.8-1+deb9u1.

We recommend that you upgrade your cairo packages." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(!isnull( res = isdpkgvuln( pkg: "cairo-perf-utils", ver: "1.14.8-1+deb9u1", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libcairo-gobject2", ver: "1.14.8-1+deb9u1", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libcairo-script-interpreter2", ver: "1.14.8-1+deb9u1", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libcairo2", ver: "1.14.8-1+deb9u1", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libcairo2-dev", ver: "1.14.8-1+deb9u1", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libcairo2-doc", ver: "1.14.8-1+deb9u1", rls: "DEB9" ) )){
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

