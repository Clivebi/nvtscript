if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.853671" );
	script_version( "2021-08-26T09:01:14+0000" );
	script_cve_id( "CVE-2019-20916", "CVE-2021-3177" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2021-08-26 09:01:14 +0000 (Thu, 26 Aug 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-07-20 23:15:00 +0000 (Tue, 20 Jul 2021)" );
	script_tag( name: "creation_date", value: "2021-04-16 04:59:34 +0000 (Fri, 16 Apr 2021)" );
	script_name( "openSUSE: Security Advisory for python3 (openSUSE-SU-2021:0331-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "SuSE Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/suse", "ssh/login/rpms",  "ssh/login/release=openSUSELeap15\\.2" );
	script_xref( name: "Advisory-ID", value: "openSUSE-SU-2021:0331-1" );
	script_xref( name: "URL", value: "https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/3AKEBUCTPHZWXJGF6EWK7HBTO726SP2Y" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'python3'
  package(s) announced via the openSUSE-SU-2021:0331-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "This update for python3 fixes the following issues:

  - CVE-2021-3177: Fixed buffer overflow in PyCArg_repr in
       _ctypes/callproc.c, which may lead to remote code execution
       (bsc#1181126).

  - Provide the newest setuptools wheel (bsc#1176262, CVE-2019-20916) in
       their correct form (bsc#1180686)." );
	script_tag( name: "affected", value: "'python3' package(s) on openSUSE Leap 15.2." );
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
if(release == "openSUSELeap15.2"){
	if(!isnull( res = isrpmvuln( pkg: "libpython3_6m1_0", rpm: "libpython3_6m1_0~3.6.12~lp152.4.17.1", rls: "openSUSELeap15.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libpython3_6m1_0-debuginfo", rpm: "libpython3_6m1_0-debuginfo~3.6.12~lp152.4.17.1", rls: "openSUSELeap15.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "python3", rpm: "python3~3.6.12~lp152.4.17.1", rls: "openSUSELeap15.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "python3-base", rpm: "python3-base~3.6.12~lp152.4.17.1", rls: "openSUSELeap15.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "python3-base-debuginfo", rpm: "python3-base-debuginfo~3.6.12~lp152.4.17.1", rls: "openSUSELeap15.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "python3-core-debugsource", rpm: "python3-core-debugsource~3.6.12~lp152.4.17.1", rls: "openSUSELeap15.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "python3-curses", rpm: "python3-curses~3.6.12~lp152.4.17.1", rls: "openSUSELeap15.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "python3-curses-debuginfo", rpm: "python3-curses-debuginfo~3.6.12~lp152.4.17.1", rls: "openSUSELeap15.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "python3-dbm", rpm: "python3-dbm~3.6.12~lp152.4.17.1", rls: "openSUSELeap15.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "python3-dbm-debuginfo", rpm: "python3-dbm-debuginfo~3.6.12~lp152.4.17.1", rls: "openSUSELeap15.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "python3-debuginfo", rpm: "python3-debuginfo~3.6.12~lp152.4.17.1", rls: "openSUSELeap15.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "python3-debugsource", rpm: "python3-debugsource~3.6.12~lp152.4.17.1", rls: "openSUSELeap15.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "python3-devel", rpm: "python3-devel~3.6.12~lp152.4.17.1", rls: "openSUSELeap15.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "python3-devel-debuginfo", rpm: "python3-devel-debuginfo~3.6.12~lp152.4.17.1", rls: "openSUSELeap15.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "python3-doc", rpm: "python3-doc~3.6.12~lp152.4.17.1", rls: "openSUSELeap15.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "python3-doc-devhelp", rpm: "python3-doc-devhelp~3.6.12~lp152.4.17.1", rls: "openSUSELeap15.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "python3-idle", rpm: "python3-idle~3.6.12~lp152.4.17.1", rls: "openSUSELeap15.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "python3-testsuite", rpm: "python3-testsuite~3.6.12~lp152.4.17.1", rls: "openSUSELeap15.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "python3-testsuite-debuginfo", rpm: "python3-testsuite-debuginfo~3.6.12~lp152.4.17.1", rls: "openSUSELeap15.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "python3-tk", rpm: "python3-tk~3.6.12~lp152.4.17.1", rls: "openSUSELeap15.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "python3-tk-debuginfo", rpm: "python3-tk-debuginfo~3.6.12~lp152.4.17.1", rls: "openSUSELeap15.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "python3-tools", rpm: "python3-tools~3.6.12~lp152.4.17.1", rls: "openSUSELeap15.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libpython3_6m1_0-32bit", rpm: "libpython3_6m1_0-32bit~3.6.12~lp152.4.17.1", rls: "openSUSELeap15.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libpython3_6m1_0-32bit-debuginfo", rpm: "libpython3_6m1_0-32bit-debuginfo~3.6.12~lp152.4.17.1", rls: "openSUSELeap15.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "python3-32bit", rpm: "python3-32bit~3.6.12~lp152.4.17.1", rls: "openSUSELeap15.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "python3-32bit-debuginfo", rpm: "python3-32bit-debuginfo~3.6.12~lp152.4.17.1", rls: "openSUSELeap15.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "python3-base-32bit", rpm: "python3-base-32bit~3.6.12~lp152.4.17.1", rls: "openSUSELeap15.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "python3-base-32bit-debuginfo", rpm: "python3-base-32bit-debuginfo~3.6.12~lp152.4.17.1", rls: "openSUSELeap15.2" ) )){
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

