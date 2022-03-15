if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.852490" );
	script_version( "2021-09-07T12:01:40+0000" );
	script_cve_id( "CVE-2019-9636" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:N/A:N" );
	script_tag( name: "last_modification", value: "2021-09-07 12:01:40 +0000 (Tue, 07 Sep 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-10-29 14:15:00 +0000 (Thu, 29 Oct 2020)" );
	script_tag( name: "creation_date", value: "2019-05-11 02:00:59 +0000 (Sat, 11 May 2019)" );
	script_name( "openSUSE: Security Advisory for python3 (openSUSE-SU-2019:1371-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2019 Greenbone Networks GmbH" );
	script_family( "SuSE Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/suse", "ssh/login/rpms",  "ssh/login/release=openSUSELeap42\\.3" );
	script_xref( name: "openSUSE-SU", value: "2019:1371-1" );
	script_xref( name: "URL", value: "https://lists.opensuse.org/opensuse-security-announce/2019-05/msg00024.html" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'python3'
  package(s) announced via the openSUSE-SU-2019:1371-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "This update for python3 fixes the following issues:

  Security issue fixed:

  - CVE-2019-9636: Fixed an information disclosure because of incorrect
  handling of Unicode encoding during NFKC normalization (bsc#1129346).

  This update was imported from the SUSE:SLE-12:Update update project.

  Patch Instructions:

  To install this openSUSE Security Update use the SUSE recommended
  installation methods
  like YaST online_update or 'zypper patch'.

  Alternatively you can run the command listed for your product:

  - openSUSE Leap 42.3:

  zypper in -t patch openSUSE-2019-1371=1" );
	script_tag( name: "affected", value: "'python3' package(s) on openSUSE Leap 42.3." );
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
	if(!isnull( res = isrpmvuln( pkg: "libpython3_4m1_0", rpm: "libpython3_4m1_0~3.4.6~12.10.1", rls: "openSUSELeap42.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libpython3_4m1_0-debuginfo", rpm: "libpython3_4m1_0-debuginfo~3.4.6~12.10.1", rls: "openSUSELeap42.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "python3", rpm: "python3~3.4.6~12.10.2", rls: "openSUSELeap42.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "python3-base", rpm: "python3-base~3.4.6~12.10.1", rls: "openSUSELeap42.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "python3-base-debuginfo", rpm: "python3-base-debuginfo~3.4.6~12.10.1", rls: "openSUSELeap42.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "python3-base-debugsource", rpm: "python3-base-debugsource~3.4.6~12.10.1", rls: "openSUSELeap42.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "python3-curses", rpm: "python3-curses~3.4.6~12.10.2", rls: "openSUSELeap42.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "python3-curses-debuginfo", rpm: "python3-curses-debuginfo~3.4.6~12.10.2", rls: "openSUSELeap42.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "python3-dbm", rpm: "python3-dbm~3.4.6~12.10.2", rls: "openSUSELeap42.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "python3-dbm-debuginfo", rpm: "python3-dbm-debuginfo~3.4.6~12.10.2", rls: "openSUSELeap42.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "python3-debuginfo", rpm: "python3-debuginfo~3.4.6~12.10.2", rls: "openSUSELeap42.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "python3-debugsource", rpm: "python3-debugsource~3.4.6~12.10.2", rls: "openSUSELeap42.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "python3-devel", rpm: "python3-devel~3.4.6~12.10.1", rls: "openSUSELeap42.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "python3-devel-debuginfo", rpm: "python3-devel-debuginfo~3.4.6~12.10.1", rls: "openSUSELeap42.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "python3-idle", rpm: "python3-idle~3.4.6~12.10.1", rls: "openSUSELeap42.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "python3-testsuite", rpm: "python3-testsuite~3.4.6~12.10.1", rls: "openSUSELeap42.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "python3-testsuite-debuginfo", rpm: "python3-testsuite-debuginfo~3.4.6~12.10.1", rls: "openSUSELeap42.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "python3-tk", rpm: "python3-tk~3.4.6~12.10.2", rls: "openSUSELeap42.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "python3-tk-debuginfo", rpm: "python3-tk-debuginfo~3.4.6~12.10.2", rls: "openSUSELeap42.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "python3-tools", rpm: "python3-tools~3.4.6~12.10.1", rls: "openSUSELeap42.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libpython3_4m1_0-32bit", rpm: "libpython3_4m1_0-32bit~3.4.6~12.10.1", rls: "openSUSELeap42.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libpython3_4m1_0-debuginfo-32bit", rpm: "libpython3_4m1_0-debuginfo-32bit~3.4.6~12.10.1", rls: "openSUSELeap42.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "python3-32bit", rpm: "python3-32bit~3.4.6~12.10.2", rls: "openSUSELeap42.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "python3-base-32bit", rpm: "python3-base-32bit~3.4.6~12.10.1", rls: "openSUSELeap42.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "python3-base-debuginfo-32bit", rpm: "python3-base-debuginfo-32bit~3.4.6~12.10.1", rls: "openSUSELeap42.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "python3-debuginfo-32bit", rpm: "python3-debuginfo-32bit~3.4.6~12.10.2", rls: "openSUSELeap42.3" ) )){
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

