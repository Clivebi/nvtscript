if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.852383" );
	script_version( "2021-09-07T12:01:40+0000" );
	script_cve_id( "CVE-2019-6798", "CVE-2019-6799" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2021-09-07 12:01:40 +0000 (Tue, 07 Sep 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-01-28 15:55:00 +0000 (Mon, 28 Jan 2019)" );
	script_tag( name: "creation_date", value: "2019-04-03 06:42:21 +0000 (Wed, 03 Apr 2019)" );
	script_name( "openSUSE: Security Advisory for phpMyAdmin (openSUSE-SU-2019:0194-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2019 Greenbone Networks GmbH" );
	script_family( "SuSE Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/suse", "ssh/login/rpms",  "ssh/login/release=(openSUSELeap42\\.3|openSUSELeap15\\.0)" );
	script_xref( name: "openSUSE-SU", value: "2019:0194-1" );
	script_xref( name: "URL", value: "https://lists.opensuse.org/opensuse-security-announce/2019-02/msg00037.html" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'phpMyAdmin'
  package(s) announced via the openSUSE-SU-2019:0194-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "This update for phpMyAdmin to version 4.8.5 fixes the following issues:

  Security issues fixed:

  - CVE-2019-6799: Fixed an arbitrary file read vulnerability (boo#1123272)

  - CVE-2019-6798: Fixed a SQL injection in the designer interface
  (boo#1123271)

  Other changes:

  * Fix rxport to SQL format not available

  * Fix QR code not shown when adding two-factor authentication to a user
  account

  * Fix issue with adding a new user in MySQL 8.0.11 and newer

  * Fix frozen interface relating to Text_Plain_Sql plugin

  * Fix missing table level operations tab

  Patch Instructions:

  To install this openSUSE Security Update use the SUSE recommended
  installation methods
  like YaST online_update or 'zypper patch'.

  Alternatively you can run the command listed for your product:

  - openSUSE Leap 42.3:

  zypper in -t patch openSUSE-2019-194=1

  - openSUSE Leap 15.0:

  zypper in -t patch openSUSE-2019-194=1

  - openSUSE Backports SLE-15:

  zypper in -t patch openSUSE-2019-194=1

  - SUSE Package Hub for SUSE Linux Enterprise 12:

  zypper in -t patch openSUSE-2019-194=1" );
	script_tag( name: "affected", value: "'phpMyAdmin' package(s) on openSUSE Leap 42.3, openSUSE Leap 15.0." );
	script_tag( name: "solution", value: "Please install the updated package(s)." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
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
if(release == "openSUSELeap42.3"){
	if(!isnull( res = isrpmvuln( pkg: "phpMyAdmin", rpm: "phpMyAdmin~4.8.5~27.1", rls: "openSUSELeap42.3" ) )){
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
if(release == "openSUSELeap15.0"){
	if(!isnull( res = isrpmvuln( pkg: "phpMyAdmin", rpm: "phpMyAdmin~4.8.5~lp150.2.15.1", rls: "openSUSELeap15.0" ) )){
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

