if(description){
	script_oid( "1.3.6.1.4.1.25623.1.1.4.2016.2932.1" );
	script_cve_id( "CVE-2016-3492", "CVE-2016-5584", "CVE-2016-5616", "CVE-2016-5624", "CVE-2016-5626", "CVE-2016-5629", "CVE-2016-6663", "CVE-2016-7440", "CVE-2016-8283" );
	script_tag( name: "creation_date", value: "2021-04-19 00:00:00 +0000 (Mon, 19 Apr 2021)" );
	script_version( "2021-08-19T02:25:52+0000" );
	script_tag( name: "last_modification", value: "2021-08-19 02:25:52 +0000 (Thu, 19 Aug 2021)" );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:S/C:N/I:N/A:C" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:L/AC:H/PR:L/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-03-05 18:23:00 +0000 (Tue, 05 Mar 2019)" );
	script_name( "SUSE: Security Advisory (SUSE-SU-2016:2932-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "SuSE Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/suse_sles", "ssh/login/rpms",  "ssh/login/release=(SLES12\\.0)" );
	script_xref( name: "Advisory-ID", value: "SUSE-SU-2016:2932-1" );
	script_xref( name: "URL", value: "https://www.suse.com/support/update/announcement/2016/suse-su-20162932-1/" );
	script_xref( name: "URL", value: "https://kb.askmonty.org/en/mariadb-10028-release-notes" );
	script_xref( name: "URL", value: "https://kb.askmonty.org/en/mariadb-10028-changelog" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'mariadb' package(s) announced via the SUSE-SU-2016:2932-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "This mariadb update to version 10.0.28 fixes the following issues
(bsc#1008318):
Security fixes:
- CVE-2016-8283: Unspecified vulnerability in subcomponent Types
 (bsc#1005582)
- CVE-2016-7440: Unspecified vulnerability in subcomponent Encryption
 (bsc#1005581)
- CVE-2016-5629: Unspecified vulnerability in subcomponent Federated
 (bsc#1005569)
- CVE-2016-5626: Unspecified vulnerability in subcomponent GIS
 (bsc#1005566)
- CVE-2016-5624: Unspecified vulnerability in subcomponent DML
 (bsc#1005564)
- CVE-2016-5616: Unspecified vulnerability in subcomponent MyISAM
 (bsc#1005562)
- CVE-2016-5584: Unspecified vulnerability in subcomponent Encryption
 (bsc#1005558)
- CVE-2016-3492: Unspecified vulnerability in subcomponent Optimizer
 (bsc#1005555)
- CVE-2016-6663: Privilege Escalation / Race Condition (bsc#1001367)
Bugfixes:
- mysql_install_db can't find data files (bsc#1006539)
- mariadb failing test sys_vars.optimizer_switch_basic (bsc#1003800)
- Notable changes:
 * XtraDB updated to 5.6.33-79.0
 * TokuDB updated to 5.6.33-79.0
 * Innodb updated to 5.6.33
 * Performance Schema updated to 5.6.33
- Release notes and upstream changelog:
 * [link moved to references]
 * [link moved to references]" );
	script_tag( name: "affected", value: "'mariadb' package(s) on SUSE Linux Enterprise Server 12, SUSE Linux Enterprise Server for SAP 12." );
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
	if(!isnull( res = isrpmvuln( pkg: "libmysqlclient-devel", rpm: "libmysqlclient-devel~10.0.28~20.16.2", rls: "SLES12.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libmysqlclient18", rpm: "libmysqlclient18~10.0.28~20.16.2", rls: "SLES12.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libmysqlclient18-32bit", rpm: "libmysqlclient18-32bit~10.0.28~20.16.2", rls: "SLES12.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libmysqlclient18-debuginfo", rpm: "libmysqlclient18-debuginfo~10.0.28~20.16.2", rls: "SLES12.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libmysqlclient18-debuginfo-32bit", rpm: "libmysqlclient18-debuginfo-32bit~10.0.28~20.16.2", rls: "SLES12.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libmysqlclient_r18", rpm: "libmysqlclient_r18~10.0.28~20.16.2", rls: "SLES12.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libmysqld-devel", rpm: "libmysqld-devel~10.0.28~20.16.2", rls: "SLES12.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libmysqld18", rpm: "libmysqld18~10.0.28~20.16.2", rls: "SLES12.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libmysqld18-debuginfo", rpm: "libmysqld18-debuginfo~10.0.28~20.16.2", rls: "SLES12.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "mariadb", rpm: "mariadb~10.0.28~20.16.2", rls: "SLES12.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "mariadb-client", rpm: "mariadb-client~10.0.28~20.16.2", rls: "SLES12.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "mariadb-client-debuginfo", rpm: "mariadb-client-debuginfo~10.0.28~20.16.2", rls: "SLES12.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "mariadb-debuginfo", rpm: "mariadb-debuginfo~10.0.28~20.16.2", rls: "SLES12.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "mariadb-debugsource", rpm: "mariadb-debugsource~10.0.28~20.16.2", rls: "SLES12.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "mariadb-errormessages", rpm: "mariadb-errormessages~10.0.28~20.16.2", rls: "SLES12.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "mariadb-tools", rpm: "mariadb-tools~10.0.28~20.16.2", rls: "SLES12.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "mariadb-tools-debuginfo", rpm: "mariadb-tools-debuginfo~10.0.28~20.16.2", rls: "SLES12.0" ) )){
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

