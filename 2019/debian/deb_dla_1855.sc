if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.891855" );
	script_version( "2021-09-03T11:01:27+0000" );
	script_cve_id( "CVE-2019-13504" );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:N/A:P" );
	script_tag( name: "last_modification", value: "2021-09-03 11:01:27 +0000 (Fri, 03 Sep 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-07-12 14:15:00 +0000 (Fri, 12 Jul 2019)" );
	script_tag( name: "creation_date", value: "2019-07-20 02:00:06 +0000 (Sat, 20 Jul 2019)" );
	script_name( "Debian LTS: Security Advisory for exiv2 (DLA-1855-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2019 Greenbone Networks GmbH" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB8" );
	script_xref( name: "URL", value: "https://lists.debian.org/debian-lts-announce/2019/07/msg00015.html" );
	script_xref( name: "URL", value: "https://security-tracker.debian.org/tracker/DLA-1855-1" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'exiv2'
  package(s) announced via the DLA-1855-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "It was discovered that there was an integer overflow vulnerability
in exiv2, a tool to manipulate images containing (eg.) EXIF metadata.

This could have resulted in a denial of service via a specially-
crafted file." );
	script_tag( name: "affected", value: "'exiv2' package(s) on Debian Linux." );
	script_tag( name: "solution", value: "For Debian 8 'Jessie', this issue has been fixed in exiv2 version
0.24-4.1+deb8u4.

We recommend that you upgrade your exiv2 packages." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(!isnull( res = isdpkgvuln( pkg: "exiv2", ver: "0.24-4.1+deb8u4", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libexiv2-13", ver: "0.24-4.1+deb8u4", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libexiv2-dbg", ver: "0.24-4.1+deb8u4", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libexiv2-dev", ver: "0.24-4.1+deb8u4", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libexiv2-doc", ver: "0.24-4.1+deb8u4", rls: "DEB8" ) )){
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
