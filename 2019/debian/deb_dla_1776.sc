if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.891776" );
	script_version( "2021-09-03T13:01:29+0000" );
	script_cve_id( "CVE-2018-19105" );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2021-09-03 13:01:29 +0000 (Fri, 03 Sep 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-05-06 00:29:00 +0000 (Mon, 06 May 2019)" );
	script_tag( name: "creation_date", value: "2019-05-06 02:00:06 +0000 (Mon, 06 May 2019)" );
	script_name( "Debian LTS: Security Advisory for librecad (DLA-1776-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2019 Greenbone Networks GmbH" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB8" );
	script_xref( name: "URL", value: "https://lists.debian.org/debian-lts-announce/2019/05/msg00005.html" );
	script_xref( name: "URL", value: "https://security-tracker.debian.org/tracker/DLA-1776-1" );
	script_xref( name: "URL", value: "https://bugs.debian.org/928477" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'librecad'
  package(s) announced via the DLA-1776-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "A vulnerability was found in LibreCAD, a computer-aided design system,
which could be exploited to crash the application or cause other
unspecified impact when opening a specially crafted file." );
	script_tag( name: "affected", value: "'librecad' package(s) on Debian Linux." );
	script_tag( name: "solution", value: "For Debian 8 'Jessie', this problem has been fixed in version
2.0.4-1+deb8u1.

We recommend that you upgrade your librecad packages." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(!isnull( res = isdpkgvuln( pkg: "librecad", ver: "2.0.4-1+deb8u1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "librecad-data", ver: "2.0.4-1+deb8u1", rls: "DEB8" ) )){
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

