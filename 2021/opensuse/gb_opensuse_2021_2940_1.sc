if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.854136" );
	script_version( "2021-09-22T08:01:20+0000" );
	script_cve_id( "CVE-2021-29921" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2021-09-22 08:01:20 +0000 (Wed, 22 Sep 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-07-20 23:15:00 +0000 (Tue, 20 Jul 2021)" );
	script_tag( name: "creation_date", value: "2021-09-04 01:02:48 +0000 (Sat, 04 Sep 2021)" );
	script_name( "openSUSE: Security Advisory for python39 (openSUSE-SU-2021:2940-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "SuSE Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/suse", "ssh/login/rpms",  "ssh/login/release=openSUSELeap15\\.3" );
	script_xref( name: "Advisory-ID", value: "openSUSE-SU-2021:2940-1" );
	script_xref( name: "URL", value: "https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/LSLJU26YTXZ6AGTZEW7EJ4Z7W6KRSZQF" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'python39'
  package(s) announced via the openSUSE-SU-2021:2940-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "This update for python39 fixes the following issues:

  - CVE-2021-29921: Fixed improper input validation of octal string IP
       addresses (bsc#1185706).

  - Use versioned python-Sphinx to avoid dependency on other version of
       Python (bsc#1183858).

  - Stop providing 'python' symbol (bsc#1185588), which means python2
       currently." );
	script_tag( name: "affected", value: "'python39' package(s) on openSUSE Leap 15.3." );
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
if(release == "openSUSELeap15.3"){
	if(!isnull( res = isrpmvuln( pkg: "python39", rpm: "python39~3.9.6~4.3.4", rls: "openSUSELeap15.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "python39-curses", rpm: "python39-curses~3.9.6~4.3.4", rls: "openSUSELeap15.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "python39-curses-debuginfo", rpm: "python39-curses-debuginfo~3.9.6~4.3.4", rls: "openSUSELeap15.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "python39-dbm", rpm: "python39-dbm~3.9.6~4.3.4", rls: "openSUSELeap15.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "python39-dbm-debuginfo", rpm: "python39-dbm-debuginfo~3.9.6~4.3.4", rls: "openSUSELeap15.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "python39-debuginfo", rpm: "python39-debuginfo~3.9.6~4.3.4", rls: "openSUSELeap15.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "python39-debugsource", rpm: "python39-debugsource~3.9.6~4.3.4", rls: "openSUSELeap15.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "python39-idle", rpm: "python39-idle~3.9.6~4.3.4", rls: "openSUSELeap15.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "python39-tk", rpm: "python39-tk~3.9.6~4.3.4", rls: "openSUSELeap15.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "python39-tk-debuginfo", rpm: "python39-tk-debuginfo~3.9.6~4.3.4", rls: "openSUSELeap15.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "python39-32bit", rpm: "python39-32bit~3.9.6~4.3.4", rls: "openSUSELeap15.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "python39-32bit-debuginfo", rpm: "python39-32bit-debuginfo~3.9.6~4.3.4", rls: "openSUSELeap15.3" ) )){
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
