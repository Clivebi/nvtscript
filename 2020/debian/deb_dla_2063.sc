if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.892063" );
	script_version( "2021-07-23T11:01:09+0000" );
	script_cve_id( "CVE-2019-3467" );
	script_tag( name: "cvss_base", value: "7.2" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:L/Au:N/C:C/I:C/A:C" );
	script_tag( name: "last_modification", value: "2021-07-23 11:01:09 +0000 (Fri, 23 Jul 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-09-25 00:15:00 +0000 (Fri, 25 Sep 2020)" );
	script_tag( name: "creation_date", value: "2020-01-16 04:00:06 +0000 (Thu, 16 Jan 2020)" );
	script_name( "Debian LTS: Security Advisory for debian-lan-config (DLA-2063-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB8" );
	script_xref( name: "URL", value: "https://lists.debian.org/debian-lts-announce/2020/01/msg00012.html" );
	script_xref( name: "URL", value: "https://security-tracker.debian.org/tracker/DLA-2063-1" );
	script_xref( name: "URL", value: "https://bugs.debian.org/947459" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'debian-lan-config'
  package(s) announced via the DLA-2063-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "In debian-lan-config < 0.26, configured too permissive ACLs for the Kerberos
admin server allowed password changes for other Kerberos user principals." );
	script_tag( name: "affected", value: "'debian-lan-config' package(s) on Debian Linux." );
	script_tag( name: "solution", value: "For Debian 8 'Jessie', this problem has been fixed in version
0.19+deb8u2.

We recommend that you upgrade your debian-lan-config packages." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(!isnull( res = isdpkgvuln( pkg: "debian-lan-config", ver: "0.19+deb8u2", rls: "DEB8" ) )){
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

