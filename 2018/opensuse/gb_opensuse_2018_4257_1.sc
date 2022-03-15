if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.852209" );
	script_version( "2021-06-28T02:00:39+0000" );
	script_cve_id( "CVE-2018-19486" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2021-06-28 02:00:39 +0000 (Mon, 28 Jun 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-04-11 03:29:00 +0000 (Thu, 11 Apr 2019)" );
	script_tag( name: "creation_date", value: "2018-12-23 04:01:41 +0100 (Sun, 23 Dec 2018)" );
	script_name( "openSUSE: Security Advisory for git (openSUSE-SU-2018:4257-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH" );
	script_family( "SuSE Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/suse", "ssh/login/rpms",  "ssh/login/release=openSUSELeap15\\.0" );
	script_xref( name: "openSUSE-SU", value: "2018:4257-1" );
	script_xref( name: "URL", value: "https://lists.opensuse.org/opensuse-security-announce/2018-12/msg00062.html" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'git'
  package(s) announced via the openSUSE-SU-2018:4257-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "This update for git fixes the following issues:

  Security issue fixed:

  - CVE-2018-19486: Fixed git that executed commands from the current
  working directory (as if '.' were at the end of $PATH) in certain cases
  involving the run_command() API and run-command.c, because there was
  (bsc#1117257).

  This update was imported from the SUSE:SLE-15:Update update project.

  Patch Instructions:

  To install this openSUSE Security Update use the SUSE recommended
  installation methods
  like YaST online_update or 'zypper patch'.

  Alternatively you can run the command listed for your product:

  - openSUSE Leap 15.0:

  zypper in -t patch openSUSE-2018-1599=1" );
	script_tag( name: "affected", value: "git on openSUSE Leap 15.0." );
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
	if(!isnull( res = isrpmvuln( pkg: "git", rpm: "git~2.16.4~lp150.2.9.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "git-arch", rpm: "git-arch~2.16.4~lp150.2.9.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "git-core", rpm: "git-core~2.16.4~lp150.2.9.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "git-core-debuginfo", rpm: "git-core-debuginfo~2.16.4~lp150.2.9.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "git-credential-gnome-keyring", rpm: "git-credential-gnome-keyring~2.16.4~lp150.2.9.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "git-credential-gnome-keyring-debuginfo", rpm: "git-credential-gnome-keyring-debuginfo~2.16.4~lp150.2.9.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "git-credential-libsecret", rpm: "git-credential-libsecret~2.16.4~lp150.2.9.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "git-credential-libsecret-debuginfo", rpm: "git-credential-libsecret-debuginfo~2.16.4~lp150.2.9.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "git-cvs", rpm: "git-cvs~2.16.4~lp150.2.9.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "git-daemon", rpm: "git-daemon~2.16.4~lp150.2.9.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "git-daemon-debuginfo", rpm: "git-daemon-debuginfo~2.16.4~lp150.2.9.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "git-debuginfo", rpm: "git-debuginfo~2.16.4~lp150.2.9.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "git-debugsource", rpm: "git-debugsource~2.16.4~lp150.2.9.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "git-email", rpm: "git-email~2.16.4~lp150.2.9.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "git-gui", rpm: "git-gui~2.16.4~lp150.2.9.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "git-p4", rpm: "git-p4~2.16.4~lp150.2.9.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "git-svn", rpm: "git-svn~2.16.4~lp150.2.9.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "git-svn-debuginfo", rpm: "git-svn-debuginfo~2.16.4~lp150.2.9.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "git-web", rpm: "git-web~2.16.4~lp150.2.9.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "gitk", rpm: "gitk~2.16.4~lp150.2.9.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "git-doc", rpm: "git-doc~2.16.4~lp150.2.9.1", rls: "openSUSELeap15.0" ) )){
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

