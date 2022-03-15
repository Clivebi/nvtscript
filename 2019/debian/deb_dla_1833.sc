if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.891833" );
	script_version( "2021-09-20T08:01:57+0000" );
	script_cve_id( "CVE-2016-3189", "CVE-2019-12900" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2021-09-20 08:01:57 +0000 (Mon, 20 Sep 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-09-14 12:18:00 +0000 (Tue, 14 Sep 2021)" );
	script_tag( name: "creation_date", value: "2019-06-25 02:00:11 +0000 (Tue, 25 Jun 2019)" );
	script_name( "Debian LTS: Security Advisory for bzip2 (DLA-1833-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2019 Greenbone Networks GmbH" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB8" );
	script_xref( name: "URL", value: "https://lists.debian.org/debian-lts-announce/2019/06/msg00021.html" );
	script_xref( name: "URL", value: "https://security-tracker.debian.org/tracker/DLA-1833-1" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'bzip2'
  package(s) announced via the DLA-1833-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "Two issues in bzip2, a high-quality block-sorting file compressor, have
been fixed. One, CVE-2019-12900, is an out-of-bounds write when using a
crafted compressed file. The other, CVE-2016-3189, is a potential
user-after-free." );
	script_tag( name: "affected", value: "'bzip2' package(s) on Debian Linux." );
	script_tag( name: "solution", value: "For Debian 8 'Jessie', these problems have been fixed in version
1.0.6-7+deb8u1.

We recommend that you upgrade your bzip2 packages." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(!isnull( res = isdpkgvuln( pkg: "bzip2", ver: "1.0.6-7+deb8u1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "bzip2-doc", ver: "1.0.6-7+deb8u1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libbz2-1.0", ver: "1.0.6-7+deb8u1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libbz2-dev", ver: "1.0.6-7+deb8u1", rls: "DEB8" ) )){
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

