if(description){
	script_oid( "1.3.6.1.4.1.25623.1.1.2.2016.1062" );
	script_cve_id( "CVE-2016-3492", "CVE-2016-5612", "CVE-2016-5616", "CVE-2016-5624", "CVE-2016-5626", "CVE-2016-5629", "CVE-2016-6662", "CVE-2016-6663", "CVE-2016-8283" );
	script_tag( name: "creation_date", value: "2020-01-23 10:41:51 +0000 (Thu, 23 Jan 2020)" );
	script_version( "2021-07-22T02:24:02+0000" );
	script_tag( name: "last_modification", value: "2021-07-22 02:24:02 +0000 (Thu, 22 Jul 2021)" );
	script_tag( name: "cvss_base", value: "10.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:C/A:C" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-06-03 17:41:00 +0000 (Mon, 03 Jun 2019)" );
	script_name( "Huawei EulerOS: Security Advisory for mariadb (EulerOS-SA-2016-1062)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
	script_family( "Huawei EulerOS Local Security Checks" );
	script_dependencies( "gb_huawei_euleros_consolidation.sc" );
	script_mandatory_keys( "ssh/login/euleros", "ssh/login/rpms",  "ssh/login/release=EULEROS\\-2\\.0SP1" );
	script_xref( name: "Advisory-ID", value: "EulerOS-SA-2016-1062" );
	script_xref( name: "URL", value: "https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2016-1062" );
	script_tag( name: "summary", value: "The remote host is missing an update for the Huawei EulerOS 'mariadb' package(s) announced via the EulerOS-SA-2016-1062 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "Unspecified vulnerability in Oracle MySQL 5.5.51 and earlier, 5.6.32 and earlier, and 5.7.14 and earlier allows remote authenticated users to affect availability via vectors related to Server: Optimizer.(CVE-2016-3492)

Unspecified vulnerability in Oracle MySQL 5.5.50 and earlier, 5.6.31 and earlier, and 5.7.13 and earlier allows remote authenticated users to affect availability via vectors related to DML.(CVE-2016-5612)

Unspecified vulnerability in Oracle MySQL 5.5.51 and earlier, 5.6.32 and earlier, and 5.7.14 and earlier allows local users to affect confidentiality, integrity, and availability via vectors related to Server: MyISAM.(CVE-2016-5616)

Unspecified vulnerability in Oracle MySQL 5.5.51 and earlier allows remote authenticated users to affect availability via vectors related to DML.(CVE-2016-5624)

Unspecified vulnerability in Oracle MySQL 5.5.51 and earlier, 5.6.32 and earlier, and 5.7.14 and earlier allows remote authenticated users to affect availability via vectors related to GIS.(CVE-2016-5626)

Unspecified vulnerability in Oracle MySQL 5.5.51 and earlier, 5.6.32 and earlier, and 5.7.14 and earlier allows remote administrators to affect availability via vectors related to Server: Federated.(CVE-2016-5629)

Oracle MySQL through 5.5.52, 5.6.x through 5.6.33, and 5.7.x through 5.7.15, MariaDB before 5.5.51, 10.0.x before 10.0.27, and 10.1.x before 10.1.17, and Percona Server before 5.5.51-38.1, 5.6.x before 5.6.32-78.0, and 5.7.x before 5.7.14-7 allow local users to create arbitrary configurations and bypass certain protection mechanisms by setting general_log_file to a my.cnf configuration. NOTE: this can be leveraged to execute arbitrary code with root privileges by setting malloc_lib.(CVE-2016-6662)

A race condition was found in the way MySQL performed MyISAM engine table repair. A database user with shell access to the server running mysqld could use this flaw to change permissions of arbitrary files writable by the mysql system user.(CVE-2016-6663)

Unspecified vulnerability in Oracle MySQL 5.5.51 and earlier, 5.6.32 and earlier, and 5.7.14 and earlier allows remote authenticated users to affect availability via vectors related to Server: Types.(CVE-2016-8283)" );
	script_tag( name: "affected", value: "'mariadb' package(s) on Huawei EulerOS V2.0SP1." );
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
if(release == "EULEROS-2.0SP1"){
	if(!isnull( res = isrpmvuln( pkg: "mariadb", rpm: "mariadb~5.5.52~1", rls: "EULEROS-2.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "mariadb-bench", rpm: "mariadb-bench~5.5.52~1", rls: "EULEROS-2.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "mariadb-devel", rpm: "mariadb-devel~5.5.52~1", rls: "EULEROS-2.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "mariadb-embedded", rpm: "mariadb-embedded~5.5.52~1", rls: "EULEROS-2.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "mariadb-libs", rpm: "mariadb-libs~5.5.52~1", rls: "EULEROS-2.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "mariadb-server", rpm: "mariadb-server~5.5.52~1", rls: "EULEROS-2.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "mariadb-test", rpm: "mariadb-test~5.5.52~1", rls: "EULEROS-2.0SP1" ) )){
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

