if(description){
	script_oid( "1.3.6.1.4.1.25623.1.1.4.2021.0018.1" );
	script_cve_id( "CVE-2020-24386" );
	script_tag( name: "creation_date", value: "2021-04-19 00:00:00 +0000 (Mon, 19 Apr 2021)" );
	script_version( "2021-08-19T02:25:52+0000" );
	script_tag( name: "last_modification", value: "2021-08-19 02:25:52 +0000 (Thu, 19 Aug 2021)" );
	script_tag( name: "cvss_base", value: "4.9" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:S/C:P/I:P/A:N" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:H/PR:L/UI:N/S:U/C:H/I:H/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-01-20 03:15:00 +0000 (Wed, 20 Jan 2021)" );
	script_name( "SUSE: Security Advisory (SUSE-SU-2021:0018-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "SuSE Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/suse_sles", "ssh/login/rpms",  "ssh/login/release=(SLES12\\.0SP2|SLES12\\.0SP3|SLES12\\.0SP4|SLES12\\.0SP5)" );
	script_xref( name: "Advisory-ID", value: "SUSE-SU-2021:0018-1" );
	script_xref( name: "URL", value: "https://www.suse.com/support/update/announcement/2021/suse-su-20210018-1/" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'dovecot22' package(s) announced via the SUSE-SU-2021:0018-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "This update for dovecot22 fixes the following issues:

CVE-2020-24386: Fixed an issue with IMAP hibernation that allowed users
 to access other users' emails (bsc#1180405)." );
	script_tag( name: "affected", value: "'dovecot22' package(s) on HPE Helion Openstack 8, SUSE Enterprise Storage 5, SUSE Linux Enterprise Server 12-SP2, SUSE Linux Enterprise Server 12-SP3, SUSE Linux Enterprise Server 12-SP4, SUSE Linux Enterprise Server 12-SP5, SUSE Linux Enterprise Server for SAP 12-SP2, SUSE Linux Enterprise Server for SAP 12-SP3, SUSE Linux Enterprise Server for SAP 12-SP4, SUSE Linux Enterprise Software Development Kit 12-SP5, SUSE OpenStack Cloud 7, SUSE OpenStack Cloud 8, SUSE OpenStack Cloud 9, SUSE OpenStack Cloud Crowbar 8, SUSE OpenStack Cloud Crowbar 9." );
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
	if(!isnull( res = isrpmvuln( pkg: "dovecot22", rpm: "dovecot22~2.2.31~19.25.1", rls: "SLES12.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "dovecot22-backend-mysql", rpm: "dovecot22-backend-mysql~2.2.31~19.25.1", rls: "SLES12.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "dovecot22-backend-mysql-debuginfo", rpm: "dovecot22-backend-mysql-debuginfo~2.2.31~19.25.1", rls: "SLES12.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "dovecot22-backend-pgsql", rpm: "dovecot22-backend-pgsql~2.2.31~19.25.1", rls: "SLES12.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "dovecot22-backend-pgsql-debuginfo", rpm: "dovecot22-backend-pgsql-debuginfo~2.2.31~19.25.1", rls: "SLES12.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "dovecot22-backend-sqlite", rpm: "dovecot22-backend-sqlite~2.2.31~19.25.1", rls: "SLES12.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "dovecot22-backend-sqlite-debuginfo", rpm: "dovecot22-backend-sqlite-debuginfo~2.2.31~19.25.1", rls: "SLES12.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "dovecot22-debuginfo", rpm: "dovecot22-debuginfo~2.2.31~19.25.1", rls: "SLES12.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "dovecot22-debugsource", rpm: "dovecot22-debugsource~2.2.31~19.25.1", rls: "SLES12.0SP2" ) )){
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
if(release == "SLES12.0SP3"){
	if(!isnull( res = isrpmvuln( pkg: "dovecot22", rpm: "dovecot22~2.2.31~19.25.1", rls: "SLES12.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "dovecot22-backend-mysql", rpm: "dovecot22-backend-mysql~2.2.31~19.25.1", rls: "SLES12.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "dovecot22-backend-mysql-debuginfo", rpm: "dovecot22-backend-mysql-debuginfo~2.2.31~19.25.1", rls: "SLES12.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "dovecot22-backend-pgsql", rpm: "dovecot22-backend-pgsql~2.2.31~19.25.1", rls: "SLES12.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "dovecot22-backend-pgsql-debuginfo", rpm: "dovecot22-backend-pgsql-debuginfo~2.2.31~19.25.1", rls: "SLES12.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "dovecot22-backend-sqlite", rpm: "dovecot22-backend-sqlite~2.2.31~19.25.1", rls: "SLES12.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "dovecot22-backend-sqlite-debuginfo", rpm: "dovecot22-backend-sqlite-debuginfo~2.2.31~19.25.1", rls: "SLES12.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "dovecot22-debuginfo", rpm: "dovecot22-debuginfo~2.2.31~19.25.1", rls: "SLES12.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "dovecot22-debugsource", rpm: "dovecot22-debugsource~2.2.31~19.25.1", rls: "SLES12.0SP3" ) )){
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
	if(!isnull( res = isrpmvuln( pkg: "dovecot22", rpm: "dovecot22~2.2.31~19.25.1", rls: "SLES12.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "dovecot22-backend-mysql", rpm: "dovecot22-backend-mysql~2.2.31~19.25.1", rls: "SLES12.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "dovecot22-backend-mysql-debuginfo", rpm: "dovecot22-backend-mysql-debuginfo~2.2.31~19.25.1", rls: "SLES12.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "dovecot22-backend-pgsql", rpm: "dovecot22-backend-pgsql~2.2.31~19.25.1", rls: "SLES12.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "dovecot22-backend-pgsql-debuginfo", rpm: "dovecot22-backend-pgsql-debuginfo~2.2.31~19.25.1", rls: "SLES12.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "dovecot22-backend-sqlite", rpm: "dovecot22-backend-sqlite~2.2.31~19.25.1", rls: "SLES12.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "dovecot22-backend-sqlite-debuginfo", rpm: "dovecot22-backend-sqlite-debuginfo~2.2.31~19.25.1", rls: "SLES12.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "dovecot22-debuginfo", rpm: "dovecot22-debuginfo~2.2.31~19.25.1", rls: "SLES12.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "dovecot22-debugsource", rpm: "dovecot22-debugsource~2.2.31~19.25.1", rls: "SLES12.0SP4" ) )){
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
	if(!isnull( res = isrpmvuln( pkg: "dovecot22", rpm: "dovecot22~2.2.31~19.25.1", rls: "SLES12.0SP5" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "dovecot22-backend-mysql", rpm: "dovecot22-backend-mysql~2.2.31~19.25.1", rls: "SLES12.0SP5" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "dovecot22-backend-mysql-debuginfo", rpm: "dovecot22-backend-mysql-debuginfo~2.2.31~19.25.1", rls: "SLES12.0SP5" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "dovecot22-backend-pgsql", rpm: "dovecot22-backend-pgsql~2.2.31~19.25.1", rls: "SLES12.0SP5" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "dovecot22-backend-pgsql-debuginfo", rpm: "dovecot22-backend-pgsql-debuginfo~2.2.31~19.25.1", rls: "SLES12.0SP5" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "dovecot22-backend-sqlite", rpm: "dovecot22-backend-sqlite~2.2.31~19.25.1", rls: "SLES12.0SP5" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "dovecot22-backend-sqlite-debuginfo", rpm: "dovecot22-backend-sqlite-debuginfo~2.2.31~19.25.1", rls: "SLES12.0SP5" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "dovecot22-debuginfo", rpm: "dovecot22-debuginfo~2.2.31~19.25.1", rls: "SLES12.0SP5" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "dovecot22-debugsource", rpm: "dovecot22-debugsource~2.2.31~19.25.1", rls: "SLES12.0SP5" ) )){
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

