if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.892222" );
	script_version( "2021-07-26T11:00:54+0000" );
	script_cve_id( "CVE-2018-20030", "CVE-2020-0093", "CVE-2020-13112", "CVE-2020-13113", "CVE-2020-13114" );
	script_tag( name: "cvss_base", value: "7.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:C" );
	script_tag( name: "last_modification", value: "2021-07-26 11:00:54 +0000 (Mon, 26 Jul 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-06-11 15:15:00 +0000 (Thu, 11 Jun 2020)" );
	script_tag( name: "creation_date", value: "2020-05-29 03:00:09 +0000 (Fri, 29 May 2020)" );
	script_name( "Debian LTS: Security Advisory for libexif (DLA-2222-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB8" );
	script_xref( name: "URL", value: "https://lists.debian.org/debian-lts-announce/2020/05/msg00025.html" );
	script_xref( name: "URL", value: "https://security-tracker.debian.org/tracker/DLA-2222-1" );
	script_xref( name: "URL", value: "https://bugs.debian.org/918730" );
	script_xref( name: "URL", value: "https://bugs.debian.org/961407" );
	script_xref( name: "URL", value: "https://bugs.debian.org/961409" );
	script_xref( name: "URL", value: "https://bugs.debian.org/961410" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'libexif'
  package(s) announced via the DLA-2222-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "Various minor vulnerabilities have been addredd in libexif, a library to
parse EXIF metadata files.

CVE-2018-20030

This issue had already been addressed via DLA-2214-1. However, upstream
provided an updated patch, so this has been followed up on.

CVE-2020-13112

Several buffer over-reads in EXIF MakerNote handling could have lead
to information disclosure and crashes. This issue is different from
already resolved CVE-2020-0093.

CVE-2020-13113

Use of uninitialized memory in EXIF Makernote handling could have
lead to crashes and potential use-after-free conditions.

CVE-2020-13114

An unrestricted size in handling Canon EXIF MakerNote data could have
lead to consumption of large amounts of compute time for decoding
EXIF data." );
	script_tag( name: "affected", value: "'libexif' package(s) on Debian Linux." );
	script_tag( name: "solution", value: "For Debian 8 'Jessie', these problems have been fixed in version
0.6.21-2+deb8u3.

We recommend that you upgrade your libexif packages." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(!isnull( res = isdpkgvuln( pkg: "libexif-dev", ver: "0.6.21-2+deb8u3", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libexif12", ver: "0.6.21-2+deb8u3", rls: "DEB8" ) )){
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
