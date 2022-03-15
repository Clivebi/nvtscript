if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.891904" );
	script_version( "2021-09-03T13:01:29+0000" );
	script_cve_id( "CVE-2019-15531" );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:N/A:P" );
	script_tag( name: "last_modification", value: "2021-09-03 13:01:29 +0000 (Fri, 03 Sep 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-08-31 00:15:00 +0000 (Sat, 31 Aug 2019)" );
	script_tag( name: "creation_date", value: "2019-08-31 02:00:06 +0000 (Sat, 31 Aug 2019)" );
	script_name( "Debian LTS: Security Advisory for libextractor (DLA-1904-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2019 Greenbone Networks GmbH" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB8" );
	script_xref( name: "URL", value: "https://lists.debian.org/debian-lts-announce/2019/08/msg00038.html" );
	script_xref( name: "URL", value: "https://security-tracker.debian.org/tracker/DLA-1904-1" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'libextractor'
  package(s) announced via the DLA-1904-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "jianglin found an issue in libextractor, a library that extracts meta-data
from files of arbitrary type.

A crafted file could result in a heap-buffer-overflow vulnerability in
function EXTRACTOR_dvi_extract_method in dvi_extractor.c." );
	script_tag( name: "affected", value: "'libextractor' package(s) on Debian Linux." );
	script_tag( name: "solution", value: "For Debian 8 'Jessie', this problem has been fixed in version
1:1.3-2+deb8u5.

We recommend that you upgrade your libextractor packages." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(!isnull( res = isdpkgvuln( pkg: "extract", ver: "1:1.3-2+deb8u5", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libextractor-dbg", ver: "1:1.3-2+deb8u5", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libextractor-dev", ver: "1:1.3-2+deb8u5", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libextractor3", ver: "1:1.3-2+deb8u5", rls: "DEB8" ) )){
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

