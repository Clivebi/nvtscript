if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.892010" );
	script_version( "2021-09-03T11:01:27+0000" );
	script_cve_id( "CVE-2014-9862" );
	script_tag( name: "cvss_base", value: "7.2" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:L/Au:N/C:C/I:C/A:C" );
	script_tag( name: "last_modification", value: "2021-09-03 11:01:27 +0000 (Fri, 03 Sep 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-09-17 14:15:00 +0000 (Thu, 17 Sep 2020)" );
	script_tag( name: "creation_date", value: "2019-11-27 03:00:13 +0000 (Wed, 27 Nov 2019)" );
	script_name( "Debian LTS: Security Advisory for bsdiff (DLA-2010-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2019 Greenbone Networks GmbH" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB8" );
	script_xref( name: "URL", value: "https://lists.debian.org/debian-lts-announce/2019/11/msg00028.html" );
	script_xref( name: "URL", value: "https://security-tracker.debian.org/tracker/DLA-2010-1" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'bsdiff'
  package(s) announced via the DLA-2010-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "An issue in bsdiff, a tool to generate/apply a patch between two binary
files, has been found.

Using a crafted patch file an integer signedness error in bspatch could be
used for a heap based buffer overflow and possibly execution of arbitrary
code." );
	script_tag( name: "affected", value: "'bsdiff' package(s) on Debian Linux." );
	script_tag( name: "solution", value: "For Debian 8 'Jessie', this problem has been fixed in version
4.3-15+deb8u1.

We recommend that you upgrade your bsdiff packages." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(!isnull( res = isdpkgvuln( pkg: "bsdiff", ver: "4.3-15+deb8u1", rls: "DEB8" ) )){
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

