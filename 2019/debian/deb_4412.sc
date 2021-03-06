if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.704412" );
	script_version( "2021-09-03T08:01:30+0000" );
	script_cve_id( "CVE-2019-6341" );
	script_tag( name: "cvss_base", value: "3.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:S/C:N/I:P/A:N" );
	script_tag( name: "last_modification", value: "2021-09-03 08:01:30 +0000 (Fri, 03 Sep 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:L/UI:R/S:C/C:L/I:L/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-05-16 02:29:00 +0000 (Thu, 16 May 2019)" );
	script_tag( name: "creation_date", value: "2019-03-19 22:00:00 +0000 (Tue, 19 Mar 2019)" );
	script_name( "Debian Security Advisory DSA 4412-1 (drupal7 - security update)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2019 Greenbone Networks GmbH" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB9" );
	script_xref( name: "URL", value: "https://www.debian.org/security/2019/dsa-4412.html" );
	script_xref( name: "URL", value: "https://security-tracker.debian.org/tracker/DSA-4412-1" );
	script_xref( name: "URL", value: "https://www.drupal.org/sa-core-2019-004" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'drupal7'
  package(s) announced via the DSA-4412-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "It was discovered that missing input sanitising in the file module of
Drupal, a fully-featured content management framework, could result in
cross-site scripting.

Please see the referenced upstream advisory for additional information." );
	script_tag( name: "affected", value: "'drupal7' package(s) on Debian Linux." );
	script_tag( name: "solution", value: "For the stable distribution (stretch), this problem has been fixed in
version 7.52-2+deb9u7.

We recommend that you upgrade your drupal7 packages." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(!isnull( res = isdpkgvuln( pkg: "drupal7", ver: "7.52-2+deb9u7", rls: "DEB9" ) )){
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

