if(description){
	script_oid( "1.3.6.1.4.1.25623.1.1.4.2020.1021.1" );
	script_cve_id( "CVE-2018-15518", "CVE-2018-19869", "CVE-2018-19873" );
	script_tag( name: "creation_date", value: "2021-04-19 00:00:00 +0000 (Mon, 19 Apr 2021)" );
	script_version( "2021-08-19T02:25:52+0000" );
	script_tag( name: "last_modification", value: "2021-08-19 02:25:52 +0000 (Thu, 19 Aug 2021)" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-09-28 09:15:00 +0000 (Mon, 28 Sep 2020)" );
	script_name( "SUSE: Security Advisory (SUSE-SU-2020:1021-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "SuSE Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/suse_sles", "ssh/login/rpms",  "ssh/login/release=(SLES12\\.0SP4|SLES12\\.0SP5)" );
	script_xref( name: "Advisory-ID", value: "SUSE-SU-2020:1021-1" );
	script_xref( name: "URL", value: "https://www.suse.com/support/update/announcement/2020/suse-su-20201021-1/" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'libqt4' package(s) announced via the SUSE-SU-2020:1021-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "This update for libqt4 fixes the following issues:

CVE-2018-15518: Fixed a double free in QXmlStreamReader (bsc#1118595)

CVE-2018-19873: Fixed a segmantation fault via a malformed BMP file
 (bsc#1118596).

CVE-2018-19869: Fixed an improper checking which might lead to a crach
 via a malformed url reference (bsc#1118599).

Added stricter toplevel asm parsing by dropping volatile qualification
 that has no effect (bsc#1121214)." );
	script_tag( name: "affected", value: "'libqt4' package(s) on SUSE Linux Enterprise Server 12-SP4, SUSE Linux Enterprise Server 12-SP5, SUSE Linux Enterprise Software Development Kit 12-SP4, SUSE Linux Enterprise Software Development Kit 12-SP5, SUSE Linux Enterprise Workstation Extension 12-SP4, SUSE Linux Enterprise Workstation Extension 12-SP5." );
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
if(release == "SLES12.0SP4"){
	if(!isnull( res = isrpmvuln( pkg: "libqt4-32bit", rpm: "libqt4-32bit~4.8.7~8.13.1", rls: "SLES12.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libqt4", rpm: "libqt4~4.8.7~8.13.1", rls: "SLES12.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libqt4-debuginfo-32bit", rpm: "libqt4-debuginfo-32bit~4.8.7~8.13.1", rls: "SLES12.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libqt4-debuginfo", rpm: "libqt4-debuginfo~4.8.7~8.13.1", rls: "SLES12.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libqt4-debugsource", rpm: "libqt4-debugsource~4.8.7~8.13.1", rls: "SLES12.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libqt4-devel-doc-debuginfo", rpm: "libqt4-devel-doc-debuginfo~4.8.7~8.13.1", rls: "SLES12.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libqt4-devel-doc-debugsource", rpm: "libqt4-devel-doc-debugsource~4.8.7~8.13.1", rls: "SLES12.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libqt4-qt3support-32bit", rpm: "libqt4-qt3support-32bit~4.8.7~8.13.1", rls: "SLES12.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libqt4-qt3support", rpm: "libqt4-qt3support~4.8.7~8.13.1", rls: "SLES12.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libqt4-qt3support-debuginfo-32bit", rpm: "libqt4-qt3support-debuginfo-32bit~4.8.7~8.13.1", rls: "SLES12.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libqt4-qt3support-debuginfo", rpm: "libqt4-qt3support-debuginfo~4.8.7~8.13.1", rls: "SLES12.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libqt4-sql-32bit", rpm: "libqt4-sql-32bit~4.8.7~8.13.1", rls: "SLES12.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libqt4-sql", rpm: "libqt4-sql~4.8.7~8.13.1", rls: "SLES12.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libqt4-sql-debuginfo-32bit", rpm: "libqt4-sql-debuginfo-32bit~4.8.7~8.13.1", rls: "SLES12.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libqt4-sql-debuginfo", rpm: "libqt4-sql-debuginfo~4.8.7~8.13.1", rls: "SLES12.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libqt4-sql-mysql", rpm: "libqt4-sql-mysql~4.8.7~8.13.1", rls: "SLES12.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libqt4-sql-mysql-debuginfo", rpm: "libqt4-sql-mysql-debuginfo~4.8.7~8.13.1", rls: "SLES12.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libqt4-sql-plugins-debugsource", rpm: "libqt4-sql-plugins-debugsource~4.8.7~8.13.1", rls: "SLES12.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libqt4-sql-sqlite", rpm: "libqt4-sql-sqlite~4.8.7~8.13.1", rls: "SLES12.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libqt4-sql-sqlite-debuginfo", rpm: "libqt4-sql-sqlite-debuginfo~4.8.7~8.13.1", rls: "SLES12.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libqt4-x11-32bit", rpm: "libqt4-x11-32bit~4.8.7~8.13.1", rls: "SLES12.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libqt4-x11", rpm: "libqt4-x11~4.8.7~8.13.1", rls: "SLES12.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libqt4-x11-debuginfo-32bit", rpm: "libqt4-x11-debuginfo-32bit~4.8.7~8.13.1", rls: "SLES12.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libqt4-x11-debuginfo", rpm: "libqt4-x11-debuginfo~4.8.7~8.13.1", rls: "SLES12.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "qt4-x11-tools", rpm: "qt4-x11-tools~4.8.7~8.13.1", rls: "SLES12.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "qt4-x11-tools-debuginfo", rpm: "qt4-x11-tools-debuginfo~4.8.7~8.13.1", rls: "SLES12.0SP4" ) )){
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
	if(!isnull( res = isrpmvuln( pkg: "libqt4-32bit", rpm: "libqt4-32bit~4.8.7~8.13.1", rls: "SLES12.0SP5" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libqt4", rpm: "libqt4~4.8.7~8.13.1", rls: "SLES12.0SP5" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libqt4-debuginfo-32bit", rpm: "libqt4-debuginfo-32bit~4.8.7~8.13.1", rls: "SLES12.0SP5" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libqt4-debuginfo", rpm: "libqt4-debuginfo~4.8.7~8.13.1", rls: "SLES12.0SP5" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libqt4-debugsource", rpm: "libqt4-debugsource~4.8.7~8.13.1", rls: "SLES12.0SP5" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libqt4-devel-doc-debuginfo", rpm: "libqt4-devel-doc-debuginfo~4.8.7~8.13.1", rls: "SLES12.0SP5" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libqt4-devel-doc-debugsource", rpm: "libqt4-devel-doc-debugsource~4.8.7~8.13.1", rls: "SLES12.0SP5" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libqt4-qt3support-32bit", rpm: "libqt4-qt3support-32bit~4.8.7~8.13.1", rls: "SLES12.0SP5" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libqt4-qt3support", rpm: "libqt4-qt3support~4.8.7~8.13.1", rls: "SLES12.0SP5" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libqt4-qt3support-debuginfo-32bit", rpm: "libqt4-qt3support-debuginfo-32bit~4.8.7~8.13.1", rls: "SLES12.0SP5" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libqt4-qt3support-debuginfo", rpm: "libqt4-qt3support-debuginfo~4.8.7~8.13.1", rls: "SLES12.0SP5" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libqt4-sql-32bit", rpm: "libqt4-sql-32bit~4.8.7~8.13.1", rls: "SLES12.0SP5" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libqt4-sql", rpm: "libqt4-sql~4.8.7~8.13.1", rls: "SLES12.0SP5" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libqt4-sql-debuginfo-32bit", rpm: "libqt4-sql-debuginfo-32bit~4.8.7~8.13.1", rls: "SLES12.0SP5" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libqt4-sql-debuginfo", rpm: "libqt4-sql-debuginfo~4.8.7~8.13.1", rls: "SLES12.0SP5" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libqt4-sql-mysql", rpm: "libqt4-sql-mysql~4.8.7~8.13.1", rls: "SLES12.0SP5" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libqt4-sql-mysql-debuginfo", rpm: "libqt4-sql-mysql-debuginfo~4.8.7~8.13.1", rls: "SLES12.0SP5" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libqt4-sql-plugins-debugsource", rpm: "libqt4-sql-plugins-debugsource~4.8.7~8.13.1", rls: "SLES12.0SP5" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libqt4-sql-sqlite", rpm: "libqt4-sql-sqlite~4.8.7~8.13.1", rls: "SLES12.0SP5" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libqt4-sql-sqlite-debuginfo", rpm: "libqt4-sql-sqlite-debuginfo~4.8.7~8.13.1", rls: "SLES12.0SP5" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libqt4-x11-32bit", rpm: "libqt4-x11-32bit~4.8.7~8.13.1", rls: "SLES12.0SP5" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libqt4-x11", rpm: "libqt4-x11~4.8.7~8.13.1", rls: "SLES12.0SP5" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libqt4-x11-debuginfo-32bit", rpm: "libqt4-x11-debuginfo-32bit~4.8.7~8.13.1", rls: "SLES12.0SP5" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libqt4-x11-debuginfo", rpm: "libqt4-x11-debuginfo~4.8.7~8.13.1", rls: "SLES12.0SP5" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "qt4-x11-tools", rpm: "qt4-x11-tools~4.8.7~8.13.1", rls: "SLES12.0SP5" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "qt4-x11-tools-debuginfo", rpm: "qt4-x11-tools-debuginfo~4.8.7~8.13.1", rls: "SLES12.0SP5" ) )){
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

