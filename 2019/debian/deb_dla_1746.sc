if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.891746" );
	script_version( "2021-09-03T13:01:29+0000" );
	script_cve_id( "CVE-2019-6341" );
	script_tag( name: "cvss_base", value: "3.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:S/C:N/I:P/A:N" );
	script_tag( name: "last_modification", value: "2021-09-03 13:01:29 +0000 (Fri, 03 Sep 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:L/UI:R/S:C/C:L/I:L/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-05-16 02:29:00 +0000 (Thu, 16 May 2019)" );
	script_tag( name: "creation_date", value: "2019-04-02 20:00:00 +0000 (Tue, 02 Apr 2019)" );
	script_name( "Debian LTS: Security Advisory for drupal7 (DLA-1746-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2019 Greenbone Networks GmbH" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB8" );
	script_xref( name: "URL", value: "https://lists.debian.org/debian-lts-announce/2019/04/msg00003.html" );
	script_xref( name: "URL", value: "https://security-tracker.debian.org/tracker/DLA-1746-1" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'drupal7'
  package(s) announced via the DLA-1746-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "It was discovered that missing input sanitising in the file module of
Drupal, a fully-featured content management framework, could result in
cross-site scripting." );
	script_tag( name: "affected", value: "'drupal7' package(s) on Debian Linux." );
	script_tag( name: "solution", value: "For Debian 8 'Jessie', this problem has been fixed in version
7.32-1+deb8u16.

We recommend that you upgrade your drupal7 packages." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(!isnull( res = isdpkgvuln( pkg: "drupal7", ver: "7.32-1+deb8u16", rls: "DEB8" ) )){
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

