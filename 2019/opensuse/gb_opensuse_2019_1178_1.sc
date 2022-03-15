if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.852410" );
	script_version( "2021-09-07T13:01:38+0000" );
	script_cve_id( "CVE-2019-9924" );
	script_tag( name: "cvss_base", value: "7.2" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:L/Au:N/C:C/I:C/A:C" );
	script_tag( name: "last_modification", value: "2021-09-07 13:01:38 +0000 (Tue, 07 Sep 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-04-11 22:29:00 +0000 (Thu, 11 Apr 2019)" );
	script_tag( name: "creation_date", value: "2019-04-09 02:01:01 +0000 (Tue, 09 Apr 2019)" );
	script_name( "openSUSE: Security Advisory for bash (openSUSE-SU-2019:1178-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2019 Greenbone Networks GmbH" );
	script_family( "SuSE Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/suse", "ssh/login/rpms",  "ssh/login/release=openSUSELeap42\\.3" );
	script_xref( name: "openSUSE-SU", value: "2019:1178-1" );
	script_xref( name: "URL", value: "https://lists.opensuse.org/opensuse-security-announce/2019-04/msg00049.html" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'bash'
  package(s) announced via the openSUSE-SU-2019:1178-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "This update for bash fixes the following issues:

  Security issue fixed:

  - CVE-2019-9924: Fixed a vulnerability in which shell did not prevent user
  BASH_CMDS allowing the user to execute any command with the permissions
  of the shell (bsc#1130324).

  This update was imported from the SUSE:SLE-12-SP2:Update update project.

  Patch Instructions:

  To install this openSUSE Security Update use the SUSE recommended
  installation methods
  like YaST online_update or 'zypper patch'.

  Alternatively you can run the command listed for your product:

  - openSUSE Leap 42.3:

  zypper in -t patch openSUSE-2019-1178=1" );
	script_tag( name: "affected", value: "'bash' package(s) on openSUSE Leap 42.3." );
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
	if(!isnull( res = isrpmvuln( pkg: "bash", rpm: "bash~4.3~83.15.1", rls: "openSUSELeap42.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "bash-debuginfo", rpm: "bash-debuginfo~4.3~83.15.1", rls: "openSUSELeap42.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "bash-debugsource", rpm: "bash-debugsource~4.3~83.15.1", rls: "openSUSELeap42.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "bash-devel", rpm: "bash-devel~4.3~83.15.1", rls: "openSUSELeap42.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "bash-loadables", rpm: "bash-loadables~4.3~83.15.1", rls: "openSUSELeap42.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "bash-loadables-debuginfo", rpm: "bash-loadables-debuginfo~4.3~83.15.1", rls: "openSUSELeap42.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libreadline6", rpm: "libreadline6~6.3~83.15.1", rls: "openSUSELeap42.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libreadline6-debuginfo", rpm: "libreadline6-debuginfo~6.3~83.15.1", rls: "openSUSELeap42.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "readline-devel", rpm: "readline-devel~6.3~83.15.1", rls: "openSUSELeap42.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "bash-debuginfo-32bit", rpm: "bash-debuginfo-32bit~4.3~83.15.1", rls: "openSUSELeap42.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libreadline6-32bit", rpm: "libreadline6-32bit~6.3~83.15.1", rls: "openSUSELeap42.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libreadline6-debuginfo-32bit", rpm: "libreadline6-debuginfo-32bit~6.3~83.15.1", rls: "openSUSELeap42.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "readline-devel-32bit", rpm: "readline-devel-32bit~6.3~83.15.1", rls: "openSUSELeap42.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "bash-doc", rpm: "bash-doc~4.3~83.15.1", rls: "openSUSELeap42.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "bash-lang", rpm: "bash-lang~4.3~83.15.1", rls: "openSUSELeap42.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "eadline-doc", rpm: "eadline-doc~6.3~83.15.1", rls: "openSUSELeap42.3" ) )){
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

