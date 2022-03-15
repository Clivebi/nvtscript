if(description){
	script_oid( "1.3.6.1.4.1.25623.1.1.4.2019.2798.1" );
	script_cve_id( "CVE-2018-20852", "CVE-2019-16056" );
	script_tag( name: "creation_date", value: "2021-04-19 00:00:00 +0000 (Mon, 19 Apr 2021)" );
	script_version( "2021-08-19T02:25:52+0000" );
	script_tag( name: "last_modification", value: "2021-08-19 02:25:52 +0000 (Thu, 19 Aug 2021)" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:N/A:N" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-08-24 17:37:00 +0000 (Mon, 24 Aug 2020)" );
	script_name( "SUSE: Security Advisory (SUSE-SU-2019:2798-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "SuSE Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/suse_sles", "ssh/login/rpms",  "ssh/login/release=(SLES12\\.0|SLES12\\.0SP4|SLES12\\.0SP5)" );
	script_xref( name: "Advisory-ID", value: "SUSE-SU-2019:2798-1" );
	script_xref( name: "URL", value: "https://www.suse.com/support/update/announcement/2019/suse-su-20192798-1/" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'python3' package(s) announced via the SUSE-SU-2019:2798-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "This update for python3 fixes the following issues:
CVE-2019-16056: Fixed a parser issue in the email module. (bsc#1149955)

CVE-2018-20852: Fixed an incorrect domain validation that could lead to
 cookies being sent to the wrong server. (bsc#1141853)" );
	script_tag( name: "affected", value: "'python3' package(s) on SUSE Linux Enterprise Desktop 12-SP4, SUSE Linux Enterprise Module for Web Scripting 12, SUSE Linux Enterprise Server 12-SP4, SUSE Linux Enterprise Server 12-SP5, SUSE Linux Enterprise Software Development Kit 12-SP4, SUSE Linux Enterprise Software Development Kit 12-SP5." );
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
if(release == "SLES12.0"){
	if(!isnull( res = isrpmvuln( pkg: "libpython3_4m1_0", rpm: "libpython3_4m1_0~3.4.6~25.34.2", rls: "SLES12.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libpython3_4m1_0-debuginfo", rpm: "libpython3_4m1_0-debuginfo~3.4.6~25.34.2", rls: "SLES12.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "python3", rpm: "python3~3.4.6~25.34.2", rls: "SLES12.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "python3-base", rpm: "python3-base~3.4.6~25.34.2", rls: "SLES12.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "python3-base-debuginfo", rpm: "python3-base-debuginfo~3.4.6~25.34.2", rls: "SLES12.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "python3-base-debugsource", rpm: "python3-base-debugsource~3.4.6~25.34.2", rls: "SLES12.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "python3-debuginfo", rpm: "python3-debuginfo~3.4.6~25.34.2", rls: "SLES12.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "python3-debugsource", rpm: "python3-debugsource~3.4.6~25.34.2", rls: "SLES12.0" ) )){
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
if(release == "SLES12.0SP4"){
	if(!isnull( res = isrpmvuln( pkg: "libpython3_4m1_0", rpm: "libpython3_4m1_0~3.4.6~25.34.2", rls: "SLES12.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libpython3_4m1_0-debuginfo", rpm: "libpython3_4m1_0-debuginfo~3.4.6~25.34.2", rls: "SLES12.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "python3", rpm: "python3~3.4.6~25.34.2", rls: "SLES12.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "python3-base", rpm: "python3-base~3.4.6~25.34.2", rls: "SLES12.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "python3-base-debuginfo", rpm: "python3-base-debuginfo~3.4.6~25.34.2", rls: "SLES12.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "python3-base-debugsource", rpm: "python3-base-debugsource~3.4.6~25.34.2", rls: "SLES12.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "python3-curses", rpm: "python3-curses~3.4.6~25.34.2", rls: "SLES12.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "python3-curses-debuginfo", rpm: "python3-curses-debuginfo~3.4.6~25.34.2", rls: "SLES12.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "python3-debuginfo", rpm: "python3-debuginfo~3.4.6~25.34.2", rls: "SLES12.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "python3-debugsource", rpm: "python3-debugsource~3.4.6~25.34.2", rls: "SLES12.0SP4" ) )){
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
if(release == "SLES12.0SP5"){
	if(!isnull( res = isrpmvuln( pkg: "libpython3_4m1_0", rpm: "libpython3_4m1_0~3.4.6~25.34.2", rls: "SLES12.0SP5" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libpython3_4m1_0-32bit", rpm: "libpython3_4m1_0-32bit~3.4.6~25.34.2", rls: "SLES12.0SP5" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libpython3_4m1_0-debuginfo", rpm: "libpython3_4m1_0-debuginfo~3.4.6~25.34.2", rls: "SLES12.0SP5" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libpython3_4m1_0-debuginfo-32bit", rpm: "libpython3_4m1_0-debuginfo-32bit~3.4.6~25.34.2", rls: "SLES12.0SP5" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "python3", rpm: "python3~3.4.6~25.34.2", rls: "SLES12.0SP5" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "python3-base", rpm: "python3-base~3.4.6~25.34.2", rls: "SLES12.0SP5" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "python3-base-debuginfo", rpm: "python3-base-debuginfo~3.4.6~25.34.2", rls: "SLES12.0SP5" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "python3-base-debuginfo-32bit", rpm: "python3-base-debuginfo-32bit~3.4.6~25.34.2", rls: "SLES12.0SP5" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "python3-base-debugsource", rpm: "python3-base-debugsource~3.4.6~25.34.2", rls: "SLES12.0SP5" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "python3-curses", rpm: "python3-curses~3.4.6~25.34.2", rls: "SLES12.0SP5" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "python3-curses-debuginfo", rpm: "python3-curses-debuginfo~3.4.6~25.34.2", rls: "SLES12.0SP5" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "python3-debuginfo", rpm: "python3-debuginfo~3.4.6~25.34.2", rls: "SLES12.0SP5" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "python3-debugsource", rpm: "python3-debugsource~3.4.6~25.34.2", rls: "SLES12.0SP5" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "python3-tk", rpm: "python3-tk~3.4.6~25.34.2", rls: "SLES12.0SP5" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "python3-tk-debuginfo", rpm: "python3-tk-debuginfo~3.4.6~25.34.2", rls: "SLES12.0SP5" ) )){
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

