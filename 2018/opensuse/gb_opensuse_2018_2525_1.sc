if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.851870" );
	script_version( "2021-06-29T02:00:29+0000" );
	script_tag( name: "last_modification", value: "2021-06-29 02:00:29 +0000 (Tue, 29 Jun 2021)" );
	script_tag( name: "creation_date", value: "2018-08-27 07:26:04 +0200 (Mon, 27 Aug 2018)" );
	script_cve_id( "CVE-2018-15605" );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:P/A:N" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2018-10-26 01:11:00 +0000 (Fri, 26 Oct 2018)" );
	script_tag( name: "qod_type", value: "package" );
	script_name( "openSUSE: Security Advisory for phpMyAdmin (openSUSE-SU-2018:2525-1)" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'phpMyAdmin'
  package(s) announced via the referenced advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "This update for phpMyAdmin to version 4.8.3 addresses multiple issues.

  Security issues fixed:

  - CVE-2018-15605: vulnerability in the file import feature allowed
  cross-site scripting via importing a specially-crafted file
  (PMASA-2018-5, boo#1105726)

  This update also contains a number of upstream bug fixes in the UI and
  behavior.

  Patch Instructions:

  To install this openSUSE Security Update use the SUSE recommended
  installation methods
  like YaST online_update or 'zypper patch'.

  Alternatively you can run the command listed for your product:

  - openSUSE Leap 42.3:

  zypper in -t patch openSUSE-2018-939=1

  - openSUSE Leap 15.0:

  zypper in -t patch openSUSE-2018-939=1" );
	script_tag( name: "affected", value: "phpMyAdmin on openSUSE Leap 42.3" );
	script_tag( name: "solution", value: "Please install the updated package(s)." );
	script_xref( name: "openSUSE-SU", value: "2018:2525-1" );
	script_xref( name: "URL", value: "https://lists.opensuse.org/opensuse-security-announce/2018-08/msg00081.html" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH" );
	script_family( "SuSE Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/suse", "ssh/login/rpms",  "ssh/login/release=openSUSELeap42\\.3" );
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
	if(!isnull( res = isrpmvuln( pkg: "phpMyAdmin", rpm: "phpMyAdmin~4.8.3~21.1", rls: "openSUSELeap42.3" ) )){
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

