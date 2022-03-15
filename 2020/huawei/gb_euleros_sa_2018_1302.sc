if(description){
	script_oid( "1.3.6.1.4.1.25623.1.1.2.2018.1302" );
	script_cve_id( "CVE-2017-10268", "CVE-2017-10378", "CVE-2017-10379", "CVE-2017-10384", "CVE-2017-3641", "CVE-2017-3653", "CVE-2018-2562", "CVE-2018-2622", "CVE-2018-2640", "CVE-2018-2665", "CVE-2018-2668", "CVE-2018-2755", "CVE-2018-2761", "CVE-2018-2767", "CVE-2018-2771", "CVE-2018-2781", "CVE-2018-2813", "CVE-2018-2817", "CVE-2018-2819" );
	script_tag( name: "creation_date", value: "2020-01-23 11:20:38 +0000 (Thu, 23 Jan 2020)" );
	script_version( "2021-07-22T02:24:02+0000" );
	script_tag( name: "last_modification", value: "2021-07-22 02:24:02 +0000 (Thu, 22 Jul 2021)" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:S/C:N/I:P/A:C" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:L/AC:H/PR:N/UI:R/S:C/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-10-03 00:03:00 +0000 (Thu, 03 Oct 2019)" );
	script_name( "Huawei EulerOS: Security Advisory for mariadb (EulerOS-SA-2018-1302)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
	script_family( "Huawei EulerOS Local Security Checks" );
	script_dependencies( "gb_huawei_euleros_consolidation.sc" );
	script_mandatory_keys( "ssh/login/euleros", "ssh/login/rpms",  "ssh/login/release=EULEROS\\-2\\.0SP2" );
	script_xref( name: "Advisory-ID", value: "EulerOS-SA-2018-1302" );
	script_xref( name: "URL", value: "https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2018-1302" );
	script_tag( name: "summary", value: "The remote host is missing an update for the Huawei EulerOS 'mariadb' package(s) announced via the EulerOS-SA-2018-1302 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "mysql: Client programs unspecified vulnerability (CPU Jul 2017) (CVE-2017-3636)

mysql: Server: DML unspecified vulnerability (CPU Jul 2017) (CVE-2017-3641)

mysql: Server: Replication unspecified vulnerability (CPU Oct 2017) (CVE-2017-10268)

mysql: Server: Optimizer unspecified vulnerability (CPU Oct 2017) (CVE-2017-10378)

mysql: Client programs unspecified vulnerability (CPU Oct 2017) (CVE-2017-10379)

mysql: Server: DDL unspecified vulnerability (CPU Oct 2017) (CVE-2017-10384)

mysql: Server: Partition unspecified vulnerability (CPU Jan 2018) (CVE-2018-2562)

mysql: Server: DDL unspecified vulnerability (CPU Jan 2018) (CVE-2018-2622)

mysql: Server: Optimizer unspecified vulnerability (CPU Jan 2018) (CVE-2018-2640)

mysql: Server: Optimizer unspecified vulnerability (CPU Jan 2018) (CVE-2018-2665)

mysql: Server: Optimizer unspecified vulnerability (CPU Jan 2018) (CVE-2018-2668)

mysql: Server: Replication unspecified vulnerability (CPU Apr 2018) (CVE-2018-2755)

mysql: Client programs unspecified vulnerability (CPU Apr 2018) (CVE-2018-2761)

mysql: Server: Locking unspecified vulnerability (CPU Apr 2018) (CVE-2018-2771)

mysql: Server: Optimizer unspecified vulnerability (CPU Apr 2018) (CVE-2018-2781)

mysql: Server: DDL unspecified vulnerability (CPU Apr 2018) (CVE-2018-2813)

mysql: Server: DDL unspecified vulnerability (CPU Apr 2018) (CVE-2018-2817)

mysql: InnoDB unspecified vulnerability (CPU Apr 2018) (CVE-2018-2819)

mysql: Server: DDL unspecified vulnerability (CPU Jul 2017) (CVE-2017-3653)

mysql: use of SSL/TLS not enforced in libmysqld (Return of BACKRONYM) (CVE-2018-2767)" );
	script_tag( name: "affected", value: "'mariadb' package(s) on Huawei EulerOS V2.0SP2." );
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
if(release == "EULEROS-2.0SP2"){
	if(!isnull( res = isrpmvuln( pkg: "mariadb", rpm: "mariadb~5.5.60~1", rls: "EULEROS-2.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "mariadb-bench", rpm: "mariadb-bench~5.5.60~1", rls: "EULEROS-2.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "mariadb-devel", rpm: "mariadb-devel~5.5.60~1", rls: "EULEROS-2.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "mariadb-libs", rpm: "mariadb-libs~5.5.60~1", rls: "EULEROS-2.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "mariadb-server", rpm: "mariadb-server~5.5.60~1", rls: "EULEROS-2.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "mariadb-test", rpm: "mariadb-test~5.5.60~1", rls: "EULEROS-2.0SP2" ) )){
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

