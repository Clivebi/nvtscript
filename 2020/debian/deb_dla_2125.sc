if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.892125" );
	script_version( "2021-07-27T02:00:54+0000" );
	script_cve_id( "CVE-2015-0258" );
	script_tag( name: "cvss_base", value: "6.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:S/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2021-07-27 02:00:54 +0000 (Tue, 27 Jul 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-10-22 00:15:00 +0000 (Thu, 22 Oct 2020)" );
	script_tag( name: "creation_date", value: "2020-02-29 04:00:12 +0000 (Sat, 29 Feb 2020)" );
	script_name( "Debian LTS: Security Advisory for collabtive (DLA-2125-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB8" );
	script_xref( name: "URL", value: "https://lists.debian.org/debian-lts-announce/2020/02/msg00031.html" );
	script_xref( name: "URL", value: "https://security-tracker.debian.org/tracker/DLA-2125-1" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'collabtive'
  package(s) announced via the DLA-2125-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "An issue has been found in collabtive, a web-based project management
software. Due to missing checks an attacker could upload scripts, which

would execute code on the server by accessing for example avatar images." );
	script_tag( name: "affected", value: "'collabtive' package(s) on Debian Linux." );
	script_tag( name: "solution", value: "For Debian 8 'Jessie', this problem has been fixed in version
2.0+dfsg-5+deb8u1.

We recommend that you upgrade your collabtive packages." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(!isnull( res = isdpkgvuln( pkg: "collabtive", ver: "2.0+dfsg-5+deb8u1", rls: "DEB8" ) )){
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

