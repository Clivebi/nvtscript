if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.891685" );
	script_version( "2021-09-03T13:01:29+0000" );
	script_cve_id( "CVE-2018-1000888", "CVE-2019-6338" );
	script_name( "Debian LTS: Security Advisory for drupal7 (DLA-1685-1)" );
	script_tag( name: "last_modification", value: "2021-09-03 13:01:29 +0000 (Fri, 03 Sep 2021)" );
	script_tag( name: "creation_date", value: "2019-02-20 00:00:00 +0100 (Wed, 20 Feb 2019)" );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-06-15 18:15:00 +0000 (Mon, 15 Jun 2020)" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	script_xref( name: "URL", value: "https://lists.debian.org/debian-lts-announce/2019/02/msg00032.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2019 Greenbone Networks GmbH" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB8" );
	script_tag( name: "affected", value: "drupal7 on Debian Linux" );
	script_tag( name: "solution", value: "For Debian 8 'Jessie', this problem has been fixed in version
7.32-1+deb8u15.

We recommend that you upgrade your drupal7 packages." );
	script_tag( name: "summary", value: "Drupal core uses the third-party PEAR Archive_Tar library. This
library has released a security update which impacts some Drupal
configurations. Refer to CVE-2018-1000888 for details. Also a possible
regression caused by CVE-2019-6339 is fixed." );
	script_tag( name: "vuldetect", value: "This check tests the installed software version using the apt package manager." );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(!isnull( res = isdpkgvuln( pkg: "drupal7", ver: "7.32-1+deb8u15", rls: "DEB8" ) )){
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

