if(description){
	script_oid( "1.3.6.1.4.1.25623.1.1.2.2019.1044" );
	script_cve_id( "CVE-2018-19131", "CVE-2018-19132" );
	script_tag( name: "creation_date", value: "2020-01-23 11:28:46 +0000 (Thu, 23 Jan 2020)" );
	script_version( "2021-07-22T02:24:02+0000" );
	script_tag( name: "last_modification", value: "2021-07-22 02:24:02 +0000 (Thu, 22 Jul 2021)" );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:P/A:N" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2018-12-11 20:54:00 +0000 (Tue, 11 Dec 2018)" );
	script_name( "Huawei EulerOS: Security Advisory for squid (EulerOS-SA-2019-1044)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
	script_family( "Huawei EulerOS Local Security Checks" );
	script_dependencies( "gb_huawei_euleros_consolidation.sc" );
	script_mandatory_keys( "ssh/login/euleros", "ssh/login/rpms",  "ssh/login/release=EULEROS\\-2\\.0SP3" );
	script_xref( name: "Advisory-ID", value: "EulerOS-SA-2019-1044" );
	script_xref( name: "URL", value: "https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2019-1044" );
	script_tag( name: "summary", value: "The remote host is missing an update for the Huawei EulerOS 'squid' package(s) announced via the EulerOS-SA-2019-1044 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "A Cross-Site Scripting vulnerability has been discovered in squid in the way X.509 certificates fields are displayed in some error pages. An attacker who can control the certificate of the origin content server may use this flaw to inject scripting code in the squid generated page, which is executed on the client's browser.(CVE-2018-19131)

A memory leak was discovered in the way Squid handles SNMP denied queries. A remote attacker may use this flaw to exhaust the resources on the server machine.(CVE-2018-19132)" );
	script_tag( name: "affected", value: "'squid' package(s) on Huawei EulerOS V2.0SP3." );
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
if(release == "EULEROS-2.0SP3"){
	if(!isnull( res = isrpmvuln( pkg: "squid", rpm: "squid~3.5.20~2.2.h2", rls: "EULEROS-2.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "squid-migration-script", rpm: "squid-migration-script~3.5.20~2.2.h2", rls: "EULEROS-2.0SP3" ) )){
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

