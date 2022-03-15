if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.852499" );
	script_version( "2021-09-07T11:01:32+0000" );
	script_cve_id( "CVE-2018-16877", "CVE-2018-16878", "CVE-2019-3885" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:N/A:N" );
	script_tag( name: "last_modification", value: "2021-09-07 11:01:32 +0000 (Tue, 07 Sep 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-05-27 18:29:00 +0000 (Mon, 27 May 2019)" );
	script_tag( name: "creation_date", value: "2019-05-16 02:01:30 +0000 (Thu, 16 May 2019)" );
	script_name( "openSUSE: Security Advisory for pacemaker (openSUSE-SU-2019:1400-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2019 Greenbone Networks GmbH" );
	script_family( "SuSE Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/suse", "ssh/login/rpms",  "ssh/login/release=openSUSELeap15\\.0" );
	script_xref( name: "openSUSE-SU", value: "2019:1400-1" );
	script_xref( name: "URL", value: "https://lists.opensuse.org/opensuse-security-announce/2019-05/msg00034.html" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'pacemaker'
  package(s) announced via the openSUSE-SU-2019:1400-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "This update for pacemaker fixes the following issues:

  Security issues fixed:

  - CVE-2019-3885: Fixed an information disclosure in log output.
  (bsc#1131357)

  - CVE-2018-16877: Fixed a local privilege escalation through insufficient
  IPC client-server authentication. (bsc#1131356)

  - CVE-2018-16878: Fixed a denial of service through insufficient
  verification inflicted preference of uncontrolled processes.
  (bsc#1131353)

  Non-security issue fixed:

  - crmd: delete resource from lrmd when appropriate to avoid timeouts with
  crmsh (bsc#1117381).

  This update was imported from the SUSE:SLE-15:Update update project.

  Patch Instructions:

  To install this openSUSE Security Update use the SUSE recommended
  installation methods
  like YaST online_update or 'zypper patch'.

  Alternatively you can run the command listed for your product:

  - openSUSE Leap 15.0:

  zypper in -t patch openSUSE-2019-1400=1" );
	script_tag( name: "affected", value: "'pacemaker' package(s) on openSUSE Leap 15.0." );
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
	if(!isnull( res = isrpmvuln( pkg: "libpacemaker-devel", rpm: "libpacemaker-devel~1.1.18+20180430.b12c320f5~lp150.2.9.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libpacemaker3", rpm: "libpacemaker3~1.1.18+20180430.b12c320f5~lp150.2.9.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libpacemaker3-debuginfo", rpm: "libpacemaker3-debuginfo~1.1.18+20180430.b12c320f5~lp150.2.9.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "pacemaker", rpm: "pacemaker~1.1.18+20180430.b12c320f5~lp150.2.9.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "pacemaker-cli", rpm: "pacemaker-cli~1.1.18+20180430.b12c320f5~lp150.2.9.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "pacemaker-cli-debuginfo", rpm: "pacemaker-cli-debuginfo~1.1.18+20180430.b12c320f5~lp150.2.9.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "pacemaker-debuginfo", rpm: "pacemaker-debuginfo~1.1.18+20180430.b12c320f5~lp150.2.9.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "pacemaker-debugsource", rpm: "pacemaker-debugsource~1.1.18+20180430.b12c320f5~lp150.2.9.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "pacemaker-remote", rpm: "pacemaker-remote~1.1.18+20180430.b12c320f5~lp150.2.9.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "pacemaker-remote-debuginfo", rpm: "pacemaker-remote-debuginfo~1.1.18+20180430.b12c320f5~lp150.2.9.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "pacemaker-cts", rpm: "pacemaker-cts~1.1.18+20180430.b12c320f5~lp150.2.9.1", rls: "openSUSELeap15.0" ) )){
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

