if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.852567" );
	script_version( "2021-09-07T09:01:33+0000" );
	script_cve_id( "CVE-2019-11703", "CVE-2019-11704", "CVE-2019-11705", "CVE-2019-11706" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2021-09-07 09:01:33 +0000 (Tue, 07 Sep 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-08-16 20:15:00 +0000 (Fri, 16 Aug 2019)" );
	script_tag( name: "creation_date", value: "2019-06-19 02:01:30 +0000 (Wed, 19 Jun 2019)" );
	script_name( "openSUSE: Security Advisory for MozillaThunderbird (openSUSE-SU-2019:1583-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2019 Greenbone Networks GmbH" );
	script_family( "SuSE Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/suse", "ssh/login/rpms",  "ssh/login/release=openSUSELeap15\\.0" );
	script_xref( name: "openSUSE-SU", value: "2019:1583-1" );
	script_xref( name: "URL", value: "https://lists.opensuse.org/opensuse-security-announce/2019-06/msg00047.html" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'MozillaThunderbird'
  package(s) announced via the openSUSE-SU-2019:1583-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "This update for MozillaThunderbird fixes the following security issues:

  - CVE-2019-11703: Fixed a heap-based buffer overflow in
  icalmemorystrdupanddequote() (bsc#1137595).

  - CVE-2019-11704: Fixed a heap-based buffer overflow in
  parser_get_next_char() (bsc#1137595).

  - CVE-2019-11705: Fixed a stack-based buffer overflow in
  icalrecur_add_bydayrules() (bsc#1137595).

  - CVE-2019-11706: Fixed a type confusion in
  icaltimezone_get_vtimezone_properties() (bsc#1137595).

  This update was imported from the SUSE:SLE-15:Update update project.

  Patch Instructions:

  To install this openSUSE Security Update use the SUSE recommended
  installation methods
  like YaST online_update or 'zypper patch'.

  Alternatively you can run the command listed for your product:

  - openSUSE Leap 15.1:

  zypper in -t patch openSUSE-2019-1583=1

  - openSUSE Leap 15.0:

  zypper in -t patch openSUSE-2019-1583=1" );
	script_tag( name: "affected", value: "'MozillaThunderbird' package(s) on openSUSE Leap 15.0." );
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
	if(!isnull( res = isrpmvuln( pkg: "MozillaThunderbird", rpm: "MozillaThunderbird~60.7.0~lp150.3.41.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "MozillaThunderbird-buildsymbols", rpm: "MozillaThunderbird-buildsymbols~60.7.0~lp150.3.41.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "MozillaThunderbird-debuginfo", rpm: "MozillaThunderbird-debuginfo~60.7.0~lp150.3.41.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "MozillaThunderbird-debugsource", rpm: "MozillaThunderbird-debugsource~60.7.0~lp150.3.41.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "MozillaThunderbird-translations-common", rpm: "MozillaThunderbird-translations-common~60.7.0~lp150.3.41.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "MozillaThunderbird-translations-other", rpm: "MozillaThunderbird-translations-other~60.7.0~lp150.3.41.1", rls: "openSUSELeap15.0" ) )){
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
