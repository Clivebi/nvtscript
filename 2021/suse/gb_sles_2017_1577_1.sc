if(description){
	script_oid( "1.3.6.1.4.1.25623.1.1.4.2017.1577.1" );
	script_tag( name: "creation_date", value: "2021-06-09 14:57:55 +0000 (Wed, 09 Jun 2021)" );
	script_version( "2021-08-19T02:25:52+0000" );
	script_tag( name: "last_modification", value: "2021-08-19 02:25:52 +0000 (Thu, 19 Aug 2021)" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:N/A:N" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N" );
	script_tag( name: "severity_origin", value: "Greenbone" );
	script_tag( name: "severity_date", value: "2021-06-18 08:34:32 +0000 (Fri, 18 Jun 2021)" );
	script_name( "SUSE: Security Advisory (SUSE-SU-2017:1577-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "SuSE Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/suse_sles", "ssh/login/rpms",  "ssh/login/release=(SLES12\\.0SP2)" );
	script_xref( name: "Advisory-ID", value: "SUSE-SU-2017:1577-1" );
	script_xref( name: "URL", value: "https://www.suse.com/support/update/announcement/2017/suse-su-20171577-1/" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'libqt5-qtbase, libqt5-qtdeclarative' package(s) announced via the SUSE-SU-2017:1577-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "This update for libqt5-qtbase and libqt5-qtdeclarative fixes the following issues:
This security issue was fixed:
- Prevent potential information leak due to race condition in QSaveFile
 (bsc#1034005).
These non-security issues were fixed:
- Fixed crash in QPlainTextEdit
- Fixed Burmese rendering issue
- Fixed reuse of C++-owned QObjects by different QML engines that could
 lead to crashes in kwin (bsc#1034402)
- Make libqt5-qtquickcontrols available in SUSE Linux Enterprise." );
	script_tag( name: "affected", value: "'libqt5-qtbase, libqt5-qtdeclarative' package(s) on SUSE Linux Enterprise Desktop 12-SP2, SUSE Linux Enterprise Server 12-SP2, SUSE Linux Enterprise Server for Raspberry Pi 12-SP2, SUSE Linux Enterprise Software Development Kit 12-SP2." );
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
if(release == "SLES12.0SP2"){
	if(!isnull( res = isrpmvuln( pkg: "libQt5Concurrent5", rpm: "libQt5Concurrent5~5.6.1~17.3.15", rls: "SLES12.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libQt5Concurrent5-debuginfo", rpm: "libQt5Concurrent5-debuginfo~5.6.1~17.3.15", rls: "SLES12.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libQt5Core5", rpm: "libQt5Core5~5.6.1~17.3.15", rls: "SLES12.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libQt5Core5-debuginfo", rpm: "libQt5Core5-debuginfo~5.6.1~17.3.15", rls: "SLES12.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libQt5DBus5", rpm: "libQt5DBus5~5.6.1~17.3.15", rls: "SLES12.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libQt5DBus5-debuginfo", rpm: "libQt5DBus5-debuginfo~5.6.1~17.3.15", rls: "SLES12.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libQt5Gui5", rpm: "libQt5Gui5~5.6.1~17.3.15", rls: "SLES12.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libQt5Gui5-debuginfo", rpm: "libQt5Gui5-debuginfo~5.6.1~17.3.15", rls: "SLES12.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libQt5Network5", rpm: "libQt5Network5~5.6.1~17.3.15", rls: "SLES12.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libQt5Network5-debuginfo", rpm: "libQt5Network5-debuginfo~5.6.1~17.3.15", rls: "SLES12.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libQt5OpenGL5", rpm: "libQt5OpenGL5~5.6.1~17.3.15", rls: "SLES12.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libQt5OpenGL5-debuginfo", rpm: "libQt5OpenGL5-debuginfo~5.6.1~17.3.15", rls: "SLES12.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libQt5PrintSupport5", rpm: "libQt5PrintSupport5~5.6.1~17.3.15", rls: "SLES12.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libQt5PrintSupport5-debuginfo", rpm: "libQt5PrintSupport5-debuginfo~5.6.1~17.3.15", rls: "SLES12.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libQt5Sql5", rpm: "libQt5Sql5~5.6.1~17.3.15", rls: "SLES12.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libQt5Sql5-debuginfo", rpm: "libQt5Sql5-debuginfo~5.6.1~17.3.15", rls: "SLES12.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libQt5Sql5-mysql", rpm: "libQt5Sql5-mysql~5.6.1~17.3.15", rls: "SLES12.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libQt5Sql5-mysql-debuginfo", rpm: "libQt5Sql5-mysql-debuginfo~5.6.1~17.3.15", rls: "SLES12.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libQt5Sql5-postgresql", rpm: "libQt5Sql5-postgresql~5.6.1~17.3.15", rls: "SLES12.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libQt5Sql5-postgresql-debuginfo", rpm: "libQt5Sql5-postgresql-debuginfo~5.6.1~17.3.15", rls: "SLES12.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libQt5Sql5-sqlite", rpm: "libQt5Sql5-sqlite~5.6.1~17.3.15", rls: "SLES12.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libQt5Sql5-sqlite-debuginfo", rpm: "libQt5Sql5-sqlite-debuginfo~5.6.1~17.3.15", rls: "SLES12.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libQt5Sql5-unixODBC", rpm: "libQt5Sql5-unixODBC~5.6.1~17.3.15", rls: "SLES12.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libQt5Sql5-unixODBC-debuginfo", rpm: "libQt5Sql5-unixODBC-debuginfo~5.6.1~17.3.15", rls: "SLES12.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libQt5Test5", rpm: "libQt5Test5~5.6.1~17.3.15", rls: "SLES12.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libQt5Test5-debuginfo", rpm: "libQt5Test5-debuginfo~5.6.1~17.3.15", rls: "SLES12.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libQt5Widgets5", rpm: "libQt5Widgets5~5.6.1~17.3.15", rls: "SLES12.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libQt5Widgets5-debuginfo", rpm: "libQt5Widgets5-debuginfo~5.6.1~17.3.15", rls: "SLES12.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libQt5Xml5", rpm: "libQt5Xml5~5.6.1~17.3.15", rls: "SLES12.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libQt5Xml5-debuginfo", rpm: "libQt5Xml5-debuginfo~5.6.1~17.3.15", rls: "SLES12.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libQtQuick5", rpm: "libQtQuick5~5.6.1~13.3.1", rls: "SLES12.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libQtQuick5-debuginfo", rpm: "libQtQuick5-debuginfo~5.6.1~13.3.1", rls: "SLES12.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libqt5-qtbase-debugsource", rpm: "libqt5-qtbase-debugsource~5.6.1~17.3.15", rls: "SLES12.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libqt5-qtdeclarative-debugsource", rpm: "libqt5-qtdeclarative-debugsource~5.6.1~13.3.1", rls: "SLES12.0SP2" ) )){
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

