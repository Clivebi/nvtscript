if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.853008" );
	script_version( "2021-08-12T12:00:56+0000" );
	script_cve_id( "CVE-2011-3389", "CVE-2011-4944", "CVE-2012-0845", "CVE-2012-1150", "CVE-2013-1752", "CVE-2013-4238", "CVE-2014-2667", "CVE-2014-4650", "CVE-2016-0772", "CVE-2016-1000110", "CVE-2016-5636", "CVE-2016-5699", "CVE-2017-18207", "CVE-2018-1000802", "CVE-2018-1060", "CVE-2018-1061", "CVE-2018-14647", "CVE-2018-20406", "CVE-2018-20852", "CVE-2019-10160", "CVE-2019-15903", "CVE-2019-16056", "CVE-2019-16935", "CVE-2019-5010", "CVE-2019-9636", "CVE-2019-9947" );
	script_tag( name: "cvss_base", value: "10.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:C/A:C" );
	script_tag( name: "last_modification", value: "2021-08-12 12:00:56 +0000 (Thu, 12 Aug 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-02-09 11:29:00 +0000 (Sat, 09 Feb 2019)" );
	script_tag( name: "creation_date", value: "2020-01-27 09:18:18 +0000 (Mon, 27 Jan 2020)" );
	script_name( "openSUSE: Security Advisory for python3 (openSUSE-SU-2020:0086_1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
	script_family( "SuSE Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/suse", "ssh/login/rpms",  "ssh/login/release=openSUSELeap15\\.1" );
	script_xref( name: "openSUSE-SU", value: "2020:0086-1" );
	script_xref( name: "URL", value: "https://lists.opensuse.org/opensuse-security-announce/2020-01/msg00040.html" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'python3'
  package(s) announced via the openSUSE-SU-2020:0086-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "This update for python3 to version 3.6.10 fixes the following issues:

  - CVE-2017-18207: Fixed a denial of service in Wave_read._read_fmt_chunk()
  (bsc#1083507).

  - CVE-2019-16056: Fixed an issue where email parsing could fail for
  multiple @ (bsc#1149955).

  - CVE-2019-15903: Fixed a heap-based buffer over-read in libexpat
  (bsc#1149429).

  This update was imported from the SUSE:SLE-15:Update update project.

  Patch Instructions:

  To install this openSUSE Security Update use the SUSE recommended
  installation methods
  like YaST online_update or 'zypper patch'.

  Alternatively you can run the command listed for your product:

  - openSUSE Leap 15.1:

  zypper in -t patch openSUSE-2020-86=1" );
	script_tag( name: "affected", value: "'python3' package(s) on openSUSE Leap 15.1." );
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
if(release == "openSUSELeap15.1"){
	if(!isnull( res = isrpmvuln( pkg: "libpython3_6m1_0", rpm: "libpython3_6m1_0~3.6.10~lp151.6.7.1", rls: "openSUSELeap15.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libpython3_6m1_0-debuginfo", rpm: "libpython3_6m1_0-debuginfo~3.6.10~lp151.6.7.1", rls: "openSUSELeap15.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "python3", rpm: "python3~3.6.10~lp151.6.7.1", rls: "openSUSELeap15.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "python3-base", rpm: "python3-base~3.6.10~lp151.6.7.1", rls: "openSUSELeap15.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "python3-base-debuginfo", rpm: "python3-base-debuginfo~3.6.10~lp151.6.7.1", rls: "openSUSELeap15.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "python3-base-debugsource", rpm: "python3-base-debugsource~3.6.10~lp151.6.7.1", rls: "openSUSELeap15.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "python3-curses", rpm: "python3-curses~3.6.10~lp151.6.7.1", rls: "openSUSELeap15.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "python3-curses-debuginfo", rpm: "python3-curses-debuginfo~3.6.10~lp151.6.7.1", rls: "openSUSELeap15.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "python3-dbm", rpm: "python3-dbm~3.6.10~lp151.6.7.1", rls: "openSUSELeap15.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "python3-dbm-debuginfo", rpm: "python3-dbm-debuginfo~3.6.10~lp151.6.7.1", rls: "openSUSELeap15.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "python3-debuginfo", rpm: "python3-debuginfo~3.6.10~lp151.6.7.1", rls: "openSUSELeap15.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "python3-debugsource", rpm: "python3-debugsource~3.6.10~lp151.6.7.1", rls: "openSUSELeap15.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "python3-devel", rpm: "python3-devel~3.6.10~lp151.6.7.1", rls: "openSUSELeap15.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "python3-devel-debuginfo", rpm: "python3-devel-debuginfo~3.6.10~lp151.6.7.1", rls: "openSUSELeap15.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "python3-idle", rpm: "python3-idle~3.6.10~lp151.6.7.1", rls: "openSUSELeap15.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "python3-testsuite", rpm: "python3-testsuite~3.6.10~lp151.6.7.1", rls: "openSUSELeap15.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "python3-testsuite-debuginfo", rpm: "python3-testsuite-debuginfo~3.6.10~lp151.6.7.1", rls: "openSUSELeap15.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "python3-tk", rpm: "python3-tk~3.6.10~lp151.6.7.1", rls: "openSUSELeap15.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "python3-tk-debuginfo", rpm: "python3-tk-debuginfo~3.6.10~lp151.6.7.1", rls: "openSUSELeap15.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "python3-tools", rpm: "python3-tools~3.6.10~lp151.6.7.1", rls: "openSUSELeap15.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libpython3_6m1_0-32bit", rpm: "libpython3_6m1_0-32bit~3.6.10~lp151.6.7.1", rls: "openSUSELeap15.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libpython3_6m1_0-32bit-debuginfo", rpm: "libpython3_6m1_0-32bit-debuginfo~3.6.10~lp151.6.7.1", rls: "openSUSELeap15.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "python3-32bit", rpm: "python3-32bit~3.6.10~lp151.6.7.1", rls: "openSUSELeap15.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "python3-32bit-debuginfo", rpm: "python3-32bit-debuginfo~3.6.10~lp151.6.7.1", rls: "openSUSELeap15.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "python3-base-32bit", rpm: "python3-base-32bit~3.6.10~lp151.6.7.1", rls: "openSUSELeap15.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "python3-base-32bit-debuginfo", rpm: "python3-base-32bit-debuginfo~3.6.10~lp151.6.7.1", rls: "openSUSELeap15.1" ) )){
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

