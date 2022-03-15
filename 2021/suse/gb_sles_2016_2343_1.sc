if(description){
	script_oid( "1.3.6.1.4.1.25623.1.1.4.2016.2343.1" );
	script_cve_id( "CVE-2016-3477", "CVE-2016-3521", "CVE-2016-3615", "CVE-2016-5440", "CVE-2016-6662" );
	script_tag( name: "creation_date", value: "2021-06-09 14:58:04 +0000 (Wed, 09 Jun 2021)" );
	script_version( "2021-08-19T02:25:52+0000" );
	script_tag( name: "last_modification", value: "2021-08-19 02:25:52 +0000 (Thu, 19 Aug 2021)" );
	script_tag( name: "cvss_base", value: "10.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:C/A:C" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-06-03 17:41:00 +0000 (Mon, 03 Jun 2019)" );
	script_name( "SUSE: Security Advisory (SUSE-SU-2016:2343-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "SuSE Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/suse_sles", "ssh/login/rpms",  "ssh/login/release=(SLES11\\.0SP3|SLES11\\.0SP4)" );
	script_xref( name: "Advisory-ID", value: "SUSE-SU-2016:2343-1" );
	script_xref( name: "URL", value: "https://www.suse.com/support/update/announcement/2016/suse-su-20162343-1/" );
	script_xref( name: "URL", value: "http://dev.mysql.com/doc/relnotes/mysql/5.5/en/news-5-5-52.html" );
	script_xref( name: "URL", value: "http://dev.mysql.com/doc/relnotes/mysql/5.5/en/news-5-5-51.html" );
	script_xref( name: "URL", value: "http://dev.mysql.com/doc/relnotes/mysql/5.5/en/news-5-5-50.html" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'mysql' package(s) announced via the SUSE-SU-2016:2343-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "This mysql update to version 5.5.52 fixes the following issues:
Security issues fixed:
- CVE-2016-3477: Fixed unspecified vulnerability in subcomponent parser
 (bsc#989913).
- CVE-2016-3521: Fixed unspecified vulnerability in subcomponent types
 (bsc#989919).
- CVE-2016-3615: Fixed unspecified vulnerability in subcomponent dml
 (bsc#989922).
- CVE-2016-5440: Fixed unspecified vulnerability in subcomponent rbr
 (bsc#989926).
- CVE-2016-6662: A malicious user with SQL and filesystem access could
 create a my.cnf in the datadir and , under certain circumstances,
 execute arbitrary code as mysql (or even root) user. (bsc#998309)
More details can be found on:
[link moved to references] [link moved to references] [link moved to references] Bugs fixed:
- bsc#967374: properly restart mysql multi instances during upgrade
- bnc#937258: multi script to restart after crash" );
	script_tag( name: "affected", value: "'mysql' package(s) on SUSE Linux Enterprise Debuginfo 11-SP3, SUSE Linux Enterprise Debuginfo 11-SP4, SUSE Linux Enterprise Point of Sale 11-SP3, SUSE Linux Enterprise Server 11-SP3, SUSE Linux Enterprise Server 11-SP4, SUSE Linux Enterprise Software Development Kit 11-SP4, SUSE Manager 2.1, SUSE Manager Proxy 2.1, SUSE OpenStack Cloud 5." );
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
if(release == "SLES11.0SP3"){
	if(!isnull( res = isrpmvuln( pkg: "libmysql55client18-32bit", rpm: "libmysql55client18-32bit~5.5.52~0.27.1", rls: "SLES11.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libmysql55client18", rpm: "libmysql55client18~5.5.52~0.27.1", rls: "SLES11.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libmysql55client_r18", rpm: "libmysql55client_r18~5.5.52~0.27.1", rls: "SLES11.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "mysql", rpm: "mysql~5.5.52~0.27.1", rls: "SLES11.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "mysql-client", rpm: "mysql-client~5.5.52~0.27.1", rls: "SLES11.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "mysql-tools", rpm: "mysql-tools~5.5.52~0.27.1", rls: "SLES11.0SP3" ) )){
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
if(release == "SLES11.0SP4"){
	if(!isnull( res = isrpmvuln( pkg: "libmysql55client18-32bit", rpm: "libmysql55client18-32bit~5.5.52~0.27.1", rls: "SLES11.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libmysql55client18", rpm: "libmysql55client18~5.5.52~0.27.1", rls: "SLES11.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libmysql55client18-x86", rpm: "libmysql55client18-x86~5.5.52~0.27.1", rls: "SLES11.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libmysql55client_r18-32bit", rpm: "libmysql55client_r18-32bit~5.5.52~0.27.1", rls: "SLES11.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libmysql55client_r18", rpm: "libmysql55client_r18~5.5.52~0.27.1", rls: "SLES11.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libmysql55client_r18-x86", rpm: "libmysql55client_r18-x86~5.5.52~0.27.1", rls: "SLES11.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "mysql", rpm: "mysql~5.5.52~0.27.1", rls: "SLES11.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "mysql-client", rpm: "mysql-client~5.5.52~0.27.1", rls: "SLES11.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "mysql-tools", rpm: "mysql-tools~5.5.52~0.27.1", rls: "SLES11.0SP4" ) )){
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

