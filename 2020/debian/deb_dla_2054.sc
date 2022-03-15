if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.892054" );
	script_version( "2021-07-28T02:00:54+0000" );
	script_cve_id( "CVE-2018-16554", "CVE-2018-17088", "CVE-2019-1010301", "CVE-2019-1010302" );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2021-07-28 02:00:54 +0000 (Wed, 28 Jul 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-12-31 20:15:00 +0000 (Tue, 31 Dec 2019)" );
	script_tag( name: "creation_date", value: "2020-01-01 03:00:11 +0000 (Wed, 01 Jan 2020)" );
	script_name( "Debian LTS: Security Advisory for jhead (DLA-2054-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB8" );
	script_xref( name: "URL", value: "https://lists.debian.org/debian-lts-announce/2019/12/msg00037.html" );
	script_xref( name: "URL", value: "https://security-tracker.debian.org/tracker/DLA-2054-1" );
	script_xref( name: "URL", value: "https://bugs.debian.org/907925" );
	script_xref( name: "URL", value: "https://bugs.debian.org/908176" );
	script_xref( name: "URL", value: "https://bugs.debian.org/932145" );
	script_xref( name: "URL", value: "https://bugs.debian.org/932146" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'jhead'
  package(s) announced via the DLA-2054-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "Multiple buffer overflows have been fixed in jhead, a program to
manipulate the non-image part of Exif compliant JPEG files." );
	script_tag( name: "affected", value: "'jhead' package(s) on Debian Linux." );
	script_tag( name: "solution", value: "For Debian 8 'Jessie', these problems have been fixed in version
1:2.97-1+deb8u2.

We recommend that you upgrade your jhead packages." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(!isnull( res = isdpkgvuln( pkg: "jhead", ver: "1:2.97-1+deb8u2", rls: "DEB8" ) )){
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

