if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.853547" );
	script_version( "2021-08-13T12:00:53+0000" );
	script_cve_id( "CVE-2020-12861", "CVE-2020-12862", "CVE-2020-12863", "CVE-2020-12864", "CVE-2020-12865", "CVE-2020-12866", "CVE-2020-12867" );
	script_tag( name: "cvss_base", value: "7.9" );
	script_tag( name: "cvss_base_vector", value: "AV:A/AC:M/Au:N/C:C/I:C/A:C" );
	script_tag( name: "last_modification", value: "2021-08-13 12:00:53 +0000 (Fri, 13 Aug 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:A/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-11-02 21:15:00 +0000 (Mon, 02 Nov 2020)" );
	script_tag( name: "creation_date", value: "2020-11-03 04:01:40 +0000 (Tue, 03 Nov 2020)" );
	script_name( "openSUSE: Security Advisory for sane-backends (openSUSE-SU-2020:1791-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
	script_family( "SuSE Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/suse", "ssh/login/rpms",  "ssh/login/release=openSUSELeap15\\.1" );
	script_xref( name: "openSUSE-SU", value: "2020:1791-1" );
	script_xref( name: "URL", value: "http://lists.opensuse.org/opensuse-security-announce/2020-10/msg00079.html" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'sane-backends'
  package(s) announced via the openSUSE-SU-2020:1791-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "This update for sane-backends fixes the following issues:

  sane-backends was updated to 1.0.31 to further improve hardware enablement
  for scanner devices (jsc#ECO-2418 jsc#SLE-15561 jsc#SLE-15560) and also
  fix various security issues:

  - CVE-2020-12861, CVE-2020-12865: Fixed an out of bounds write (bsc#1172524)

  - CVE-2020-12862, CVE-2020-12863, CVE-2020-12864, : Fixed an out of bounds
  read (bsc#1172524)

  - CVE-2020-12866, CVE-2020-12867: Fixed a null pointer dereference
  (bsc#1172524)

  This update was imported from the SUSE:SLE-15:Update update project.


  Patch Instructions:

  To install this openSUSE Security Update use the SUSE recommended
  installation methods
  like YaST online_update or 'zypper patch'.

  Alternatively you can run the command listed for your product:

  - openSUSE Leap 15.1:

  zypper in -t patch openSUSE-2020-1791=1" );
	script_tag( name: "affected", value: "'sane-backends' package(s) on openSUSE Leap 15.1." );
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
	if(!isnull( res = isrpmvuln( pkg: "sane-backends", rpm: "sane-backends~1.0.31~lp151.6.3.1", rls: "openSUSELeap15.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "sane-backends-autoconfig", rpm: "sane-backends-autoconfig~1.0.31~lp151.6.3.1", rls: "openSUSELeap15.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "sane-backends-debuginfo", rpm: "sane-backends-debuginfo~1.0.31~lp151.6.3.1", rls: "openSUSELeap15.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "sane-backends-debugsource", rpm: "sane-backends-debugsource~1.0.31~lp151.6.3.1", rls: "openSUSELeap15.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "sane-backends-devel", rpm: "sane-backends-devel~1.0.31~lp151.6.3.1", rls: "openSUSELeap15.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "sane-backends-32bit", rpm: "sane-backends-32bit~1.0.31~lp151.6.3.1", rls: "openSUSELeap15.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "sane-backends-32bit-debuginfo", rpm: "sane-backends-32bit-debuginfo~1.0.31~lp151.6.3.1", rls: "openSUSELeap15.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "sane-backends-devel-32bit", rpm: "sane-backends-devel-32bit~1.0.31~lp151.6.3.1", rls: "openSUSELeap15.1" ) )){
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

