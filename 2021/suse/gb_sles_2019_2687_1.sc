if(description){
	script_oid( "1.3.6.1.4.1.25623.1.1.4.2019.2687.1" );
	script_cve_id( "CVE-2019-2614", "CVE-2019-2627", "CVE-2019-2737", "CVE-2019-2739", "CVE-2019-2740", "CVE-2019-2805" );
	script_tag( name: "creation_date", value: "2021-04-19 00:00:00 +0000 (Mon, 19 Apr 2021)" );
	script_version( "2021-08-19T02:25:52+0000" );
	script_tag( name: "last_modification", value: "2021-08-19 02:25:52 +0000 (Thu, 19 Aug 2021)" );
	script_tag( name: "cvss_base", value: "4.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:S/C:N/I:N/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-08-24 17:37:00 +0000 (Mon, 24 Aug 2020)" );
	script_name( "SUSE: Security Advisory (SUSE-SU-2019:2687-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "SuSE Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/suse_sles", "ssh/login/rpms",  "ssh/login/release=(SLES12\\.0SP4)" );
	script_xref( name: "Advisory-ID", value: "SUSE-SU-2019:2687-1" );
	script_xref( name: "URL", value: "https://www.suse.com/support/update/announcement/2019/suse-su-20192687-1/" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'mariadb-100' package(s) announced via the SUSE-SU-2019:2687-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "This update for mariadb-100 fixes the following issues:

Updated to MariaDB 10.0.40-1.

Security issues fixed:
CVE-2019-2805, CVE-2019-2740, CVE-2019-2739, CVE-2019-2737,
 CVE-2019-2614, CVE-2019-2627. (bsc#1132826) (bsc#1141798)." );
	script_tag( name: "affected", value: "'mariadb-100' package(s) on SUSE Linux Enterprise Desktop 12-SP4, SUSE Linux Enterprise Server 12-SP4, SUSE Linux Enterprise Software Development Kit 12-SP4, SUSE Linux Enterprise Workstation Extension 12-SP4." );
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
	if(!isnull( res = isrpmvuln( pkg: "libmysqlclient18", rpm: "libmysqlclient18~10.0.40.1~2.9.1", rls: "SLES12.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libmysqlclient18-32bit", rpm: "libmysqlclient18-32bit~10.0.40.1~2.9.1", rls: "SLES12.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libmysqlclient18-debuginfo", rpm: "libmysqlclient18-debuginfo~10.0.40.1~2.9.1", rls: "SLES12.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libmysqlclient18-debuginfo-32bit", rpm: "libmysqlclient18-debuginfo-32bit~10.0.40.1~2.9.1", rls: "SLES12.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "mariadb-100-debuginfo", rpm: "mariadb-100-debuginfo~10.0.40.1~2.9.1", rls: "SLES12.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "mariadb-100-debugsource", rpm: "mariadb-100-debugsource~10.0.40.1~2.9.1", rls: "SLES12.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "mariadb-100-errormessages", rpm: "mariadb-100-errormessages~10.0.40.1~2.9.1", rls: "SLES12.0SP4" ) )){
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
