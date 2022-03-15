if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.851672" );
	script_version( "2021-06-25T02:00:34+0000" );
	script_tag( name: "last_modification", value: "2021-06-25 02:00:34 +0000 (Fri, 25 Jun 2021)" );
	script_tag( name: "creation_date", value: "2017-12-30 07:36:58 +0100 (Sat, 30 Dec 2017)" );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-04-30 18:36:00 +0000 (Tue, 30 Apr 2019)" );
	script_tag( name: "qod_type", value: "package" );
	script_cve_id( "CVE-2017-1000499" );
	script_name( "openSUSE: Security Advisory for phpMyAdmin (openSUSE-SU-2017:3448-1)" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'phpMyAdmin'
  package(s) announced via the referenced advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "This update for phpMyAdmin to version 4.7.7 fixes a security issue and
  bugs.

  The following vulnerability was fixed:

  - By deceiving a user to click on a crafted URL, it was possible to
  perform harmful database
  operations (bsc#1074066, PMASA-2017-09)

  This update also contains all upstream improvements and bugfixes in
  version 4.7.7:

  - various display and UI fixes

  - PHP error fixes

  - Improved deteciton of MySQL server needing SSL connections

  - Support JSON datatype on MariaDB 10.2.7 and newer

  - Fix constructing ALTER query with AFTER

  - Fix changing password on MariaDB cluster" );
	script_tag( name: "affected", value: "phpMyAdmin on openSUSE Leap 42.3, openSUSE Leap 42.2" );
	script_tag( name: "solution", value: "Please install the updated package(s)." );
	script_xref( name: "openSUSE-SU", value: "2017:3448-1" );
	script_xref( name: "URL", value: "https://lists.opensuse.org/opensuse-security-announce/2017-12/msg00095.html" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2017 Greenbone Networks GmbH" );
	script_family( "SuSE Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/suse", "ssh/login/rpms",  "ssh/login/release=(openSUSELeap42\\.2|openSUSELeap42\\.3)" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-rpm.inc.sc");
release = rpm_get_ssh_release();
if(!release){
	exit( 0 );
}
res = "";
report = "";
if(release == "openSUSELeap42.2"){
	if(!isnull( res = isrpmvuln( pkg: "phpMyAdmin", rpm: "phpMyAdmin~4.7.7~33.12.1", rls: "openSUSELeap42.2" ) )){
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
}
if(release == "openSUSELeap42.3"){
	if(!isnull( res = isrpmvuln( pkg: "phpMyAdmin", rpm: "phpMyAdmin~4.7.7~6.1", rls: "openSUSELeap42.3" ) )){
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
}
exit( 0 );

