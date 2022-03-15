if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.852608" );
	script_version( "2021-09-07T10:01:34+0000" );
	script_cve_id( "CVE-2019-13045" );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2021-09-07 10:01:34 +0000 (Tue, 07 Sep 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-07-03 15:15:00 +0000 (Wed, 03 Jul 2019)" );
	script_tag( name: "creation_date", value: "2019-07-03 02:00:43 +0000 (Wed, 03 Jul 2019)" );
	script_name( "openSUSE: Security Advisory for irssi (openSUSE-SU-2019:1690-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2019 Greenbone Networks GmbH" );
	script_family( "SuSE Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/suse", "ssh/login/rpms",  "ssh/login/release=(openSUSELeap42\\.3|openSUSELeap15\\.0)" );
	script_xref( name: "openSUSE-SU", value: "2019:1690-1" );
	script_xref( name: "URL", value: "https://lists.opensuse.org/opensuse-security-announce/2019-07/msg00006.html" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'irssi'
  package(s) announced via the openSUSE-SU-2019:1690-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "This update for irssi fixes the following issues:

  irssi was updated to 1.1.3:

  - CVE-2019-13045: Fix a use after free issue when sending the SASL login
  on (automatic and manual) reconnects (#1055, #1058) (boo#1139802)

  - Fix regression of #779 where autolog_ignore_targets would not matching
  itemless windows anymore (#1012, #1013)

  Patch Instructions:

  To install this openSUSE Security Update use the SUSE recommended
  installation methods
  like YaST online_update or 'zypper patch'.

  Alternatively you can run the command listed for your product:

  - openSUSE Leap 42.3:

  zypper in -t patch openSUSE-2019-1690=1

  - openSUSE Leap 15.1:

  zypper in -t patch openSUSE-2019-1690=1

  - openSUSE Leap 15.0:

  zypper in -t patch openSUSE-2019-1690=1

  - openSUSE Backports SLE-15:

  zypper in -t patch openSUSE-2019-1690=1

  - SUSE Package Hub for SUSE Linux Enterprise 12:

  zypper in -t patch openSUSE-2019-1690=1" );
	script_tag( name: "affected", value: "'irssi' package(s) on openSUSE Leap 42.3, openSUSE Leap 15.0." );
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
	if(!isnull( res = isrpmvuln( pkg: "irssi", rpm: "irssi~1.1.3~33.1", rls: "openSUSELeap42.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "irssi-debuginfo", rpm: "irssi-debuginfo~1.1.3~33.1", rls: "openSUSELeap42.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "irssi-debugsource", rpm: "irssi-debugsource~1.1.3~33.1", rls: "openSUSELeap42.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "irssi-devel", rpm: "irssi-devel~1.1.3~33.1", rls: "openSUSELeap42.3" ) )){
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
	if(!isnull( res = isrpmvuln( pkg: "irssi", rpm: "irssi~1.1.3~lp150.33.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "irssi-debuginfo", rpm: "irssi-debuginfo~1.1.3~lp150.33.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "irssi-debugsource", rpm: "irssi-debugsource~1.1.3~lp150.33.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "irssi-devel", rpm: "irssi-devel~1.1.3~lp150.33.1", rls: "openSUSELeap15.0" ) )){
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

