if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.891841" );
	script_version( "2021-09-03T08:01:30+0000" );
	script_cve_id( "CVE-2019-12481", "CVE-2019-12482", "CVE-2019-12483" );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2021-09-03 08:01:30 +0000 (Fri, 03 Sep 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-08-24 17:37:00 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2019-07-01 02:00:09 +0000 (Mon, 01 Jul 2019)" );
	script_name( "Debian LTS: Security Advisory for gpac (DLA-1841-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2019 Greenbone Networks GmbH" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB8" );
	script_xref( name: "URL", value: "https://lists.debian.org/debian-lts-announce/2019/06/msg00030.html" );
	script_xref( name: "URL", value: "https://security-tracker.debian.org/tracker/DLA-1841-1" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'gpac'
  package(s) announced via the DLA-1841-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "Three issues have been found for gpac, an Open Source multimedia
framework.
Two of them are NULL pointer dereferences and one of them is a heap-based
buffer overflow." );
	script_tag( name: "affected", value: "'gpac' package(s) on Debian Linux." );
	script_tag( name: "solution", value: "For Debian 8 'Jessie', these problems have been fixed in version
0.5.0+svn5324~dfsg1-1+deb8u4.

We recommend that you upgrade your gpac packages." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(!isnull( res = isdpkgvuln( pkg: "gpac", ver: "0.5.0+svn5324~dfsg1-1+deb8u4", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "gpac-dbg", ver: "0.5.0+svn5324~dfsg1-1+deb8u4", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "gpac-modules-base", ver: "0.5.0+svn5324~dfsg1-1+deb8u4", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libgpac-dbg", ver: "0.5.0+svn5324~dfsg1-1+deb8u4", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libgpac-dev", ver: "0.5.0+svn5324~dfsg1-1+deb8u4", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libgpac3", ver: "0.5.0+svn5324~dfsg1-1+deb8u4", rls: "DEB8" ) )){
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

