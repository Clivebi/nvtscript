if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.891971" );
	script_version( "2021-09-03T11:01:27+0000" );
	script_cve_id( "CVE-2019-18408" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:P" );
	script_tag( name: "last_modification", value: "2021-09-03 11:01:27 +0000 (Fri, 03 Sep 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-11-01 11:15:00 +0000 (Fri, 01 Nov 2019)" );
	script_tag( name: "creation_date", value: "2019-10-27 03:00:09 +0000 (Sun, 27 Oct 2019)" );
	script_name( "Debian LTS: Security Advisory for libarchive (DLA-1971-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2019 Greenbone Networks GmbH" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB8" );
	script_xref( name: "URL", value: "https://lists.debian.org/debian-lts-announce/2019/10/msg00034.html" );
	script_xref( name: "URL", value: "https://security-tracker.debian.org/tracker/DLA-1971-1" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'libarchive'
  package(s) announced via the DLA-1971-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "An issue has been found in libarchive, a multi-format archive and
compression library.

In case of a crafted archive containing several parts and one part being
corrupt, there would be an use-after-free for the next part of the
archive." );
	script_tag( name: "affected", value: "'libarchive' package(s) on Debian Linux." );
	script_tag( name: "solution", value: "For Debian 8 'Jessie', this problem has been fixed in version
3.1.2-11+deb8u8.

We recommend that you upgrade your libarchive packages." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(!isnull( res = isdpkgvuln( pkg: "bsdcpio", ver: "3.1.2-11+deb8u8", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "bsdtar", ver: "3.1.2-11+deb8u8", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libarchive-dev", ver: "3.1.2-11+deb8u8", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libarchive13", ver: "3.1.2-11+deb8u8", rls: "DEB8" ) )){
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

