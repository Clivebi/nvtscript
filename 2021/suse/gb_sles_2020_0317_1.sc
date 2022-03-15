if(description){
	script_oid( "1.3.6.1.4.1.25623.1.1.4.2020.0317.1" );
	script_cve_id( "CVE-2018-19870", "CVE-2018-19872", "CVE-2020-0569" );
	script_tag( name: "creation_date", value: "2021-04-19 00:00:00 +0000 (Mon, 19 Apr 2021)" );
	script_version( "2021-08-19T02:25:52+0000" );
	script_tag( name: "last_modification", value: "2021-08-19 02:25:52 +0000 (Thu, 19 Aug 2021)" );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-09-28 09:15:00 +0000 (Mon, 28 Sep 2020)" );
	script_name( "SUSE: Security Advisory (SUSE-SU-2020:0317-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "SuSE Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/suse_sles", "ssh/login/rpms",  "ssh/login/release=(SLES12\\.0SP3|SLES12\\.0SP4|SLES12\\.0SP5)" );
	script_xref( name: "Advisory-ID", value: "SUSE-SU-2020:0317-1" );
	script_xref( name: "URL", value: "https://www.suse.com/support/update/announcement/2020/suse-su-20200317-1/" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'libqt5-qtbase' package(s) announced via the SUSE-SU-2020:0317-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "This update for libqt5-qtbase fixes the following issues:

Security issues fixed:
CVE-2020-0569: Fixed a potential local code execution by loading plugins
 from CWD (bsc#1161167).

CVE-2018-19870: Fixed an improper check in QImage allocation which could
 allow Denial of Service when opening crafted gif files (bsc#1118597).

CVE-2018-19872: Fixed an issue which could allow a division by zero
 leading to crash (bsc#1130246)." );
	script_tag( name: "affected", value: "'libqt5-qtbase' package(s) on SUSE Enterprise Storage 5, SUSE Linux Enterprise Desktop 12-SP4, SUSE Linux Enterprise Server 12-SP3, SUSE Linux Enterprise Server 12-SP4, SUSE Linux Enterprise Server 12-SP5, SUSE Linux Enterprise Server for SAP 12-SP3, SUSE Linux Enterprise Software Development Kit 12-SP4, SUSE Linux Enterprise Software Development Kit 12-SP5, SUSE OpenStack Cloud 8." );
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
if(release == "SLES12.0SP3"){
	if(!isnull( res = isrpmvuln( pkg: "libQt5Concurrent5", rpm: "libQt5Concurrent5~5.6.2~6.22.1", rls: "SLES12.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libQt5Concurrent5-debuginfo", rpm: "libQt5Concurrent5-debuginfo~5.6.2~6.22.1", rls: "SLES12.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libQt5Core5", rpm: "libQt5Core5~5.6.2~6.22.1", rls: "SLES12.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libQt5Core5-debuginfo", rpm: "libQt5Core5-debuginfo~5.6.2~6.22.1", rls: "SLES12.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libQt5DBus5", rpm: "libQt5DBus5~5.6.2~6.22.1", rls: "SLES12.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libQt5DBus5-debuginfo", rpm: "libQt5DBus5-debuginfo~5.6.2~6.22.1", rls: "SLES12.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libQt5Gui5", rpm: "libQt5Gui5~5.6.2~6.22.1", rls: "SLES12.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libQt5Gui5-debuginfo", rpm: "libQt5Gui5-debuginfo~5.6.2~6.22.1", rls: "SLES12.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libQt5Network5", rpm: "libQt5Network5~5.6.2~6.22.1", rls: "SLES12.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libQt5Network5-debuginfo", rpm: "libQt5Network5-debuginfo~5.6.2~6.22.1", rls: "SLES12.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libQt5OpenGL5", rpm: "libQt5OpenGL5~5.6.2~6.22.1", rls: "SLES12.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libQt5OpenGL5-debuginfo", rpm: "libQt5OpenGL5-debuginfo~5.6.2~6.22.1", rls: "SLES12.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libQt5PrintSupport5", rpm: "libQt5PrintSupport5~5.6.2~6.22.1", rls: "SLES12.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libQt5PrintSupport5-debuginfo", rpm: "libQt5PrintSupport5-debuginfo~5.6.2~6.22.1", rls: "SLES12.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libQt5Sql5", rpm: "libQt5Sql5~5.6.2~6.22.1", rls: "SLES12.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libQt5Sql5-debuginfo", rpm: "libQt5Sql5-debuginfo~5.6.2~6.22.1", rls: "SLES12.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libQt5Sql5-mysql", rpm: "libQt5Sql5-mysql~5.6.2~6.22.1", rls: "SLES12.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libQt5Sql5-mysql-debuginfo", rpm: "libQt5Sql5-mysql-debuginfo~5.6.2~6.22.1", rls: "SLES12.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libQt5Sql5-postgresql", rpm: "libQt5Sql5-postgresql~5.6.2~6.22.1", rls: "SLES12.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libQt5Sql5-postgresql-debuginfo", rpm: "libQt5Sql5-postgresql-debuginfo~5.6.2~6.22.1", rls: "SLES12.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libQt5Sql5-sqlite", rpm: "libQt5Sql5-sqlite~5.6.2~6.22.1", rls: "SLES12.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libQt5Sql5-sqlite-debuginfo", rpm: "libQt5Sql5-sqlite-debuginfo~5.6.2~6.22.1", rls: "SLES12.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libQt5Sql5-unixODBC", rpm: "libQt5Sql5-unixODBC~5.6.2~6.22.1", rls: "SLES12.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libQt5Sql5-unixODBC-debuginfo", rpm: "libQt5Sql5-unixODBC-debuginfo~5.6.2~6.22.1", rls: "SLES12.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libQt5Test5", rpm: "libQt5Test5~5.6.2~6.22.1", rls: "SLES12.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libQt5Test5-debuginfo", rpm: "libQt5Test5-debuginfo~5.6.2~6.22.1", rls: "SLES12.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libQt5Widgets5", rpm: "libQt5Widgets5~5.6.2~6.22.1", rls: "SLES12.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libQt5Widgets5-debuginfo", rpm: "libQt5Widgets5-debuginfo~5.6.2~6.22.1", rls: "SLES12.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libQt5Xml5", rpm: "libQt5Xml5~5.6.2~6.22.1", rls: "SLES12.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libQt5Xml5-debuginfo", rpm: "libQt5Xml5-debuginfo~5.6.2~6.22.1", rls: "SLES12.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libqt5-qtbase-debugsource", rpm: "libqt5-qtbase-debugsource~5.6.2~6.22.1", rls: "SLES12.0SP3" ) )){
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
	if(!isnull( res = isrpmvuln( pkg: "libQt5Concurrent5", rpm: "libQt5Concurrent5~5.6.2~6.22.1", rls: "SLES12.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libQt5Concurrent5-debuginfo", rpm: "libQt5Concurrent5-debuginfo~5.6.2~6.22.1", rls: "SLES12.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libQt5Core5", rpm: "libQt5Core5~5.6.2~6.22.1", rls: "SLES12.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libQt5Core5-debuginfo", rpm: "libQt5Core5-debuginfo~5.6.2~6.22.1", rls: "SLES12.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libQt5DBus5", rpm: "libQt5DBus5~5.6.2~6.22.1", rls: "SLES12.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libQt5DBus5-debuginfo", rpm: "libQt5DBus5-debuginfo~5.6.2~6.22.1", rls: "SLES12.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libQt5Gui5", rpm: "libQt5Gui5~5.6.2~6.22.1", rls: "SLES12.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libQt5Gui5-debuginfo", rpm: "libQt5Gui5-debuginfo~5.6.2~6.22.1", rls: "SLES12.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libQt5Network5", rpm: "libQt5Network5~5.6.2~6.22.1", rls: "SLES12.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libQt5Network5-debuginfo", rpm: "libQt5Network5-debuginfo~5.6.2~6.22.1", rls: "SLES12.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libQt5OpenGL5", rpm: "libQt5OpenGL5~5.6.2~6.22.1", rls: "SLES12.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libQt5OpenGL5-debuginfo", rpm: "libQt5OpenGL5-debuginfo~5.6.2~6.22.1", rls: "SLES12.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libQt5PrintSupport5", rpm: "libQt5PrintSupport5~5.6.2~6.22.1", rls: "SLES12.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libQt5PrintSupport5-debuginfo", rpm: "libQt5PrintSupport5-debuginfo~5.6.2~6.22.1", rls: "SLES12.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libQt5Sql5", rpm: "libQt5Sql5~5.6.2~6.22.1", rls: "SLES12.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libQt5Sql5-debuginfo", rpm: "libQt5Sql5-debuginfo~5.6.2~6.22.1", rls: "SLES12.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libQt5Sql5-mysql", rpm: "libQt5Sql5-mysql~5.6.2~6.22.1", rls: "SLES12.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libQt5Sql5-mysql-debuginfo", rpm: "libQt5Sql5-mysql-debuginfo~5.6.2~6.22.1", rls: "SLES12.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libQt5Sql5-postgresql", rpm: "libQt5Sql5-postgresql~5.6.2~6.22.1", rls: "SLES12.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libQt5Sql5-postgresql-debuginfo", rpm: "libQt5Sql5-postgresql-debuginfo~5.6.2~6.22.1", rls: "SLES12.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libQt5Sql5-sqlite", rpm: "libQt5Sql5-sqlite~5.6.2~6.22.1", rls: "SLES12.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libQt5Sql5-sqlite-debuginfo", rpm: "libQt5Sql5-sqlite-debuginfo~5.6.2~6.22.1", rls: "SLES12.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libQt5Sql5-unixODBC", rpm: "libQt5Sql5-unixODBC~5.6.2~6.22.1", rls: "SLES12.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libQt5Sql5-unixODBC-debuginfo", rpm: "libQt5Sql5-unixODBC-debuginfo~5.6.2~6.22.1", rls: "SLES12.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libQt5Test5", rpm: "libQt5Test5~5.6.2~6.22.1", rls: "SLES12.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libQt5Test5-debuginfo", rpm: "libQt5Test5-debuginfo~5.6.2~6.22.1", rls: "SLES12.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libQt5Widgets5", rpm: "libQt5Widgets5~5.6.2~6.22.1", rls: "SLES12.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libQt5Widgets5-debuginfo", rpm: "libQt5Widgets5-debuginfo~5.6.2~6.22.1", rls: "SLES12.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libQt5Xml5", rpm: "libQt5Xml5~5.6.2~6.22.1", rls: "SLES12.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libQt5Xml5-debuginfo", rpm: "libQt5Xml5-debuginfo~5.6.2~6.22.1", rls: "SLES12.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libqt5-qtbase-debugsource", rpm: "libqt5-qtbase-debugsource~5.6.2~6.22.1", rls: "SLES12.0SP4" ) )){
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
	if(!isnull( res = isrpmvuln( pkg: "libQt5Concurrent5", rpm: "libQt5Concurrent5~5.6.2~6.22.1", rls: "SLES12.0SP5" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libQt5Concurrent5-debuginfo", rpm: "libQt5Concurrent5-debuginfo~5.6.2~6.22.1", rls: "SLES12.0SP5" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libQt5Core5", rpm: "libQt5Core5~5.6.2~6.22.1", rls: "SLES12.0SP5" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libQt5Core5-debuginfo", rpm: "libQt5Core5-debuginfo~5.6.2~6.22.1", rls: "SLES12.0SP5" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libQt5DBus5", rpm: "libQt5DBus5~5.6.2~6.22.1", rls: "SLES12.0SP5" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libQt5DBus5-debuginfo", rpm: "libQt5DBus5-debuginfo~5.6.2~6.22.1", rls: "SLES12.0SP5" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libQt5Gui5", rpm: "libQt5Gui5~5.6.2~6.22.1", rls: "SLES12.0SP5" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libQt5Gui5-debuginfo", rpm: "libQt5Gui5-debuginfo~5.6.2~6.22.1", rls: "SLES12.0SP5" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libQt5Network5", rpm: "libQt5Network5~5.6.2~6.22.1", rls: "SLES12.0SP5" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libQt5Network5-debuginfo", rpm: "libQt5Network5-debuginfo~5.6.2~6.22.1", rls: "SLES12.0SP5" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libQt5OpenGL5", rpm: "libQt5OpenGL5~5.6.2~6.22.1", rls: "SLES12.0SP5" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libQt5OpenGL5-debuginfo", rpm: "libQt5OpenGL5-debuginfo~5.6.2~6.22.1", rls: "SLES12.0SP5" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libQt5PrintSupport5", rpm: "libQt5PrintSupport5~5.6.2~6.22.1", rls: "SLES12.0SP5" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libQt5PrintSupport5-debuginfo", rpm: "libQt5PrintSupport5-debuginfo~5.6.2~6.22.1", rls: "SLES12.0SP5" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libQt5Sql5", rpm: "libQt5Sql5~5.6.2~6.22.1", rls: "SLES12.0SP5" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libQt5Sql5-debuginfo", rpm: "libQt5Sql5-debuginfo~5.6.2~6.22.1", rls: "SLES12.0SP5" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libQt5Sql5-mysql", rpm: "libQt5Sql5-mysql~5.6.2~6.22.1", rls: "SLES12.0SP5" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libQt5Sql5-mysql-debuginfo", rpm: "libQt5Sql5-mysql-debuginfo~5.6.2~6.22.1", rls: "SLES12.0SP5" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libQt5Sql5-postgresql", rpm: "libQt5Sql5-postgresql~5.6.2~6.22.1", rls: "SLES12.0SP5" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libQt5Sql5-postgresql-debuginfo", rpm: "libQt5Sql5-postgresql-debuginfo~5.6.2~6.22.1", rls: "SLES12.0SP5" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libQt5Sql5-sqlite", rpm: "libQt5Sql5-sqlite~5.6.2~6.22.1", rls: "SLES12.0SP5" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libQt5Sql5-sqlite-debuginfo", rpm: "libQt5Sql5-sqlite-debuginfo~5.6.2~6.22.1", rls: "SLES12.0SP5" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libQt5Sql5-unixODBC", rpm: "libQt5Sql5-unixODBC~5.6.2~6.22.1", rls: "SLES12.0SP5" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libQt5Sql5-unixODBC-debuginfo", rpm: "libQt5Sql5-unixODBC-debuginfo~5.6.2~6.22.1", rls: "SLES12.0SP5" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libQt5Test5", rpm: "libQt5Test5~5.6.2~6.22.1", rls: "SLES12.0SP5" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libQt5Test5-debuginfo", rpm: "libQt5Test5-debuginfo~5.6.2~6.22.1", rls: "SLES12.0SP5" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libQt5Widgets5", rpm: "libQt5Widgets5~5.6.2~6.22.1", rls: "SLES12.0SP5" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libQt5Widgets5-debuginfo", rpm: "libQt5Widgets5-debuginfo~5.6.2~6.22.1", rls: "SLES12.0SP5" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libQt5Xml5", rpm: "libQt5Xml5~5.6.2~6.22.1", rls: "SLES12.0SP5" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libQt5Xml5-debuginfo", rpm: "libQt5Xml5-debuginfo~5.6.2~6.22.1", rls: "SLES12.0SP5" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libqt5-qtbase-debugsource", rpm: "libqt5-qtbase-debugsource~5.6.2~6.22.1", rls: "SLES12.0SP5" ) )){
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

