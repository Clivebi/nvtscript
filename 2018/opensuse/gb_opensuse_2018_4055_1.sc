if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.852174" );
	script_version( "2021-06-25T11:00:33+0000" );
	script_cve_id( "CVE-2018-19211" );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:N/A:P" );
	script_tag( name: "last_modification", value: "2021-06-25 11:00:33 +0000 (Fri, 25 Jun 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-04-23 13:15:00 +0000 (Tue, 23 Apr 2019)" );
	script_tag( name: "creation_date", value: "2018-12-10 07:38:58 +0100 (Mon, 10 Dec 2018)" );
	script_name( "openSUSE: Security Advisory for ncurses (openSUSE-SU-2018:4055-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH" );
	script_family( "SuSE Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/suse", "ssh/login/rpms",  "ssh/login/release=openSUSELeap15\\.0" );
	script_xref( name: "openSUSE-SU", value: "2018:4055-1" );
	script_xref( name: "URL", value: "https://lists.opensuse.org/opensuse-security-announce/2018-12/msg00022.html" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'ncurses'
  package(s) announced via the openSUSE-SU-2018:4055-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "This update for ncurses fixes the following issues:

  Security issue fixed:

  - CVE-2018-19211: Fixed denial of service issue that was triggered by a
  NULL pointer dereference at function _nc_parse_entry (bsc#1115929).

  Non-security issue fixed:

  - Remove scree.xterm from terminfo data base as with this screen uses
  fallback TERM=screen (bsc#1103320).

  This update was imported from the SUSE:SLE-15:Update update project.

  Patch Instructions:

  To install this openSUSE Security Update use the SUSE recommended
  installation methods
  like YaST online_update or 'zypper patch'.

  Alternatively you can run the command listed for your product:

  - openSUSE Leap 15.0:

  zypper in -t patch openSUSE-2018-1516=1" );
	script_tag( name: "affected", value: "ncurses on openSUSE Leap 15.0." );
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
	if(!isnull( res = isrpmvuln( pkg: "libncurses5", rpm: "libncurses5~6.1~lp150.4.3.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libncurses5-debuginfo", rpm: "libncurses5-debuginfo~6.1~lp150.4.3.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libncurses6", rpm: "libncurses6~6.1~lp150.4.3.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libncurses6-debuginfo", rpm: "libncurses6-debuginfo~6.1~lp150.4.3.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "ncurses-debugsource", rpm: "ncurses-debugsource~6.1~lp150.4.3.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "ncurses-devel", rpm: "ncurses-devel~6.1~lp150.4.3.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "ncurses-devel-debuginfo", rpm: "ncurses-devel-debuginfo~6.1~lp150.4.3.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "ncurses-utils", rpm: "ncurses-utils~6.1~lp150.4.3.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "ncurses-utils-debuginfo", rpm: "ncurses-utils-debuginfo~6.1~lp150.4.3.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "ncurses5-devel", rpm: "ncurses5-devel~6.1~lp150.4.3.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "tack", rpm: "tack~6.1~lp150.4.3.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "tack-debuginfo", rpm: "tack-debuginfo~6.1~lp150.4.3.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "terminfo", rpm: "terminfo~6.1~lp150.4.3.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "terminfo-base", rpm: "terminfo-base~6.1~lp150.4.3.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "terminfo-iterm", rpm: "terminfo-iterm~6.1~lp150.4.3.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "terminfo-screen", rpm: "terminfo-screen~6.1~lp150.4.3.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libncurses5-32bit", rpm: "libncurses5-32bit~6.1~lp150.4.3.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libncurses5-32bit-debuginfo", rpm: "libncurses5-32bit-debuginfo~6.1~lp150.4.3.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libncurses6-32bit", rpm: "libncurses6-32bit~6.1~lp150.4.3.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libncurses6-32bit-debuginfo", rpm: "libncurses6-32bit-debuginfo~6.1~lp150.4.3.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "ncurses-devel-32bit", rpm: "ncurses-devel-32bit~6.1~lp150.4.3.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "ncurses-devel-32bit-debuginfo", rpm: "ncurses-devel-32bit-debuginfo~6.1~lp150.4.3.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "ncurses5-devel-32bit", rpm: "ncurses5-devel-32bit~6.1~lp150.4.3.1", rls: "openSUSELeap15.0" ) )){
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

