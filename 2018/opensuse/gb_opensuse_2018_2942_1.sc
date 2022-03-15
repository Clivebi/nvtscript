if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.852064" );
	script_version( "2021-06-25T11:00:33+0000" );
	script_cve_id( "CVE-2018-16741", "CVE-2018-16742", "CVE-2018-16743", "CVE-2018-16744", "CVE-2018-16745" );
	script_tag( name: "cvss_base", value: "7.2" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:L/Au:N/C:C/I:C/A:C" );
	script_tag( name: "last_modification", value: "2021-06-25 11:00:33 +0000 (Fri, 25 Jun 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-10-03 00:03:00 +0000 (Thu, 03 Oct 2019)" );
	script_tag( name: "creation_date", value: "2018-10-26 06:40:40 +0200 (Fri, 26 Oct 2018)" );
	script_name( "openSUSE: Security Advisory for mgetty (openSUSE-SU-2018:2942-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH" );
	script_family( "SuSE Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/suse", "ssh/login/rpms",  "ssh/login/release=openSUSELeap15\\.0" );
	script_xref( name: "openSUSE-SU", value: "2018:2942-1" );
	script_xref( name: "URL", value: "https://lists.opensuse.org/opensuse-security-announce/2018-09/msg00085.html" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'mgetty'
  package(s) announced via the openSUSE-SU-2018:2942-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "This update for mgetty fixes the following issues:

  - CVE-2018-16741: The function do_activate() did not properly sanitize
  shell metacharacters to prevent command injection (bsc#1108752).

  - CVE-2018-16745: The mail_to parameter was not sanitized, leading to a
  buffer
  overflow if long untrusted input reached it (bsc#1108756).

  - CVE-2018-16744: The mail_to parameter was not sanitized, leading to
  command injection if untrusted input reached reach it (bsc#1108757).

  - CVE-2018-16742: Prevent stack-based buffer overflow that could have been
  triggered via a command-line parameter (bsc#1108762).

  - CVE-2018-16743: The command-line parameter username wsa passed
  unsanitized to strcpy(), which could have caused a stack-based buffer
  overflow (bsc#1108761).

  This update was imported from the SUSE:SLE-15:Update update project.

  Patch Instructions:

  To install this openSUSE Security Update use the SUSE recommended
  installation methods
  like YaST online_update or 'zypper patch'.

  Alternatively you can run the command listed for your product:

  - openSUSE Leap 15.0:

  zypper in -t patch openSUSE-2018-1080=1" );
	script_tag( name: "affected", value: "mgetty on openSUSE Leap 15.0." );
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
	if(!isnull( res = isrpmvuln( pkg: "g3utils", rpm: "g3utils~1.1.37~lp150.2.3.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "g3utils-debuginfo", rpm: "g3utils-debuginfo~1.1.37~lp150.2.3.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "mgetty", rpm: "mgetty~1.1.37~lp150.2.3.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "mgetty-debuginfo", rpm: "mgetty-debuginfo~1.1.37~lp150.2.3.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "mgetty-debugsource", rpm: "mgetty-debugsource~1.1.37~lp150.2.3.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "sendfax", rpm: "sendfax~1.1.37~lp150.2.3.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "sendfax-debuginfo", rpm: "sendfax-debuginfo~1.1.37~lp150.2.3.1", rls: "openSUSELeap15.0" ) )){
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

