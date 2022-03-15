if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.851890" );
	script_version( "2021-06-25T02:00:34+0000" );
	script_tag( name: "last_modification", value: "2021-06-25 02:00:34 +0000 (Fri, 25 Jun 2021)" );
	script_tag( name: "creation_date", value: "2018-09-15 07:24:32 +0200 (Sat, 15 Sep 2018)" );
	script_cve_id( "CVE-2018-1060", "CVE-2018-1061" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-01-15 20:15:00 +0000 (Wed, 15 Jan 2020)" );
	script_tag( name: "qod_type", value: "package" );
	script_name( "openSUSE: Security Advisory for python3 (openSUSE-SU-2018:2712-1)" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'python3'
  package(s) announced via the referenced advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "This update for python3 provides the following fixes:

  These security issues were fixed:

  - CVE-2018-1061: Prevent catastrophic backtracking in the
  difflib.IS_LINE_JUNK method. An attacker could have used this flaw to
  cause denial of service (bsc#1088004).

  - CVE-2018-1060: Prevent catastrophic backtracking in pop3lib's apop()
  method. An attacker could have used this flaw to cause denial of service
  (bsc#1088009).

  These non-security issues were fixed:

  - Sort files and directories when creating tarfile archives so that they
  are created in a more predictable way. (bsc#1086001)

  - Add -fwrapv to OPTS (bsc#1107030)

  This update was imported from the SUSE:SLE-12:Update update project.

  Patch Instructions:

  To install this openSUSE Security Update use the SUSE recommended
  installation methods
  like YaST online_update or 'zypper patch'.

  Alternatively you can run the command listed for your product:

  - openSUSE Leap 42.3:

  zypper in -t patch openSUSE-2018-1001=1" );
	script_tag( name: "affected", value: "python3 on openSUSE Leap 42.3" );
	script_tag( name: "solution", value: "Please install the updated package(s)." );
	script_xref( name: "openSUSE-SU", value: "2018:2712-1" );
	script_xref( name: "URL", value: "https://lists.opensuse.org/opensuse-security-announce/2018-09/msg00024.html" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH" );
	script_family( "SuSE Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/suse", "ssh/login/rpms",  "ssh/login/release=openSUSELeap42\\.3" );
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
	if(!isnull( res = isrpmvuln( pkg: "libpython3_4m1_0", rpm: "libpython3_4m1_0~3.4.6~12.6.1", rls: "openSUSELeap42.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libpython3_4m1_0-debuginfo", rpm: "libpython3_4m1_0-debuginfo~3.4.6~12.6.1", rls: "openSUSELeap42.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "python3", rpm: "python3~3.4.6~12.6.1", rls: "openSUSELeap42.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "python3-base", rpm: "python3-base~3.4.6~12.6.1", rls: "openSUSELeap42.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "python3-base-debuginfo", rpm: "python3-base-debuginfo~3.4.6~12.6.1", rls: "openSUSELeap42.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "python3-base-debugsource", rpm: "python3-base-debugsource~3.4.6~12.6.1", rls: "openSUSELeap42.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "python3-curses", rpm: "python3-curses~3.4.6~12.6.1", rls: "openSUSELeap42.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "python3-curses-debuginfo", rpm: "python3-curses-debuginfo~3.4.6~12.6.1", rls: "openSUSELeap42.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "python3-dbm", rpm: "python3-dbm~3.4.6~12.6.1", rls: "openSUSELeap42.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "python3-dbm-debuginfo", rpm: "python3-dbm-debuginfo~3.4.6~12.6.1", rls: "openSUSELeap42.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "python3-debuginfo", rpm: "python3-debuginfo~3.4.6~12.6.1", rls: "openSUSELeap42.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "python3-debugsource", rpm: "python3-debugsource~3.4.6~12.6.1", rls: "openSUSELeap42.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "python3-devel", rpm: "python3-devel~3.4.6~12.6.1", rls: "openSUSELeap42.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "python3-devel-debuginfo", rpm: "python3-devel-debuginfo~3.4.6~12.6.1", rls: "openSUSELeap42.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "python3-idle", rpm: "python3-idle~3.4.6~12.6.1", rls: "openSUSELeap42.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "python3-testsuite", rpm: "python3-testsuite~3.4.6~12.6.1", rls: "openSUSELeap42.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "python3-testsuite-debuginfo", rpm: "python3-testsuite-debuginfo~3.4.6~12.6.1", rls: "openSUSELeap42.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "python3-tk", rpm: "python3-tk~3.4.6~12.6.1", rls: "openSUSELeap42.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "python3-tk-debuginfo", rpm: "python3-tk-debuginfo~3.4.6~12.6.1", rls: "openSUSELeap42.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "python3-tools", rpm: "python3-tools~3.4.6~12.6.1", rls: "openSUSELeap42.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libpython3_4m1_0-32bit", rpm: "libpython3_4m1_0-32bit~3.4.6~12.6.1", rls: "openSUSELeap42.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libpython3_4m1_0-debuginfo-32bit", rpm: "libpython3_4m1_0-debuginfo-32bit~3.4.6~12.6.1", rls: "openSUSELeap42.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "python3-32bit", rpm: "python3-32bit~3.4.6~12.6.1", rls: "openSUSELeap42.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "python3-base-32bit", rpm: "python3-base-32bit~3.4.6~12.6.1", rls: "openSUSELeap42.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "python3-base-debuginfo-32bit", rpm: "python3-base-debuginfo-32bit~3.4.6~12.6.1", rls: "openSUSELeap42.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "python3-debuginfo-32bit", rpm: "python3-debuginfo-32bit~3.4.6~12.6.1", rls: "openSUSELeap42.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "python3-doc", rpm: "python3-doc~3.4.6~12.6.1", rls: "openSUSELeap42.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "python3-doc-pdf", rpm: "python3-doc-pdf~3.4.6~12.6.1", rls: "openSUSELeap42.3" ) )){
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

