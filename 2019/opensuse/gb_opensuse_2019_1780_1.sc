if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.852624" );
	script_version( "2021-09-07T12:01:40+0000" );
	script_cve_id( "CVE-2018-14332" );
	script_tag( name: "cvss_base", value: "1.9" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:M/Au:N/C:N/I:N/A:P" );
	script_tag( name: "last_modification", value: "2021-09-07 12:01:40 +0000 (Tue, 07 Sep 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-07-21 12:15:00 +0000 (Sun, 21 Jul 2019)" );
	script_tag( name: "creation_date", value: "2019-07-22 02:01:02 +0000 (Mon, 22 Jul 2019)" );
	script_name( "openSUSE: Security Advisory for clementine (openSUSE-SU-2019:1780-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2019 Greenbone Networks GmbH" );
	script_family( "SuSE Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/suse", "ssh/login/rpms",  "ssh/login/release=openSUSELeap15\\.0" );
	script_xref( name: "openSUSE-SU", value: "2019:1780-1" );
	script_xref( name: "URL", value: "https://lists.opensuse.org/opensuse-security-announce/2019-07/msg00038.html" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'clementine'
  package(s) announced via the openSUSE-SU-2019:1780-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "This update for clementine fixes the following issues:

  - CVE-2018-14332: Fixed a NULL ptr dereference (crash) in the moodbar
  pipeline (boo#1103041)

  Patch Instructions:

  To install this openSUSE Security Update use the SUSE recommended
  installation methods
  like YaST online_update or 'zypper patch'.

  Alternatively you can run the command listed for your product:

  - openSUSE Leap 15.1:

  zypper in -t patch openSUSE-2019-1780=1

  - openSUSE Leap 15.0:

  zypper in -t patch openSUSE-2019-1780=1

  - openSUSE Backports SLE-15:

  zypper in -t patch openSUSE-2019-1780=1" );
	script_tag( name: "affected", value: "'clementine' package(s) on openSUSE Leap 15.0." );
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
if(release == "openSUSELeap15.0"){
	if(!isnull( res = isrpmvuln( pkg: "clementine", rpm: "clementine~1.3.1~lp150.2.3.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "clementine-debuginfo", rpm: "clementine-debuginfo~1.3.1~lp150.2.3.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "clementine-debugsource", rpm: "clementine-debugsource~1.3.1~lp150.2.3.1", rls: "openSUSELeap15.0" ) )){
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

