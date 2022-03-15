if(description){
	script_oid( "1.3.6.1.4.1.25623.1.1.2.2019.1436" );
	script_cve_id( "CVE-2015-5621", "CVE-2018-1000116", "CVE-2018-18066" );
	script_tag( name: "creation_date", value: "2020-01-23 11:46:37 +0000 (Thu, 23 Jan 2020)" );
	script_version( "2021-07-22T02:24:02+0000" );
	script_tag( name: "last_modification", value: "2021-07-22 02:24:02 +0000 (Thu, 22 Jul 2021)" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-08-24 17:37:00 +0000 (Mon, 24 Aug 2020)" );
	script_name( "Huawei EulerOS: Security Advisory for net-snmp (EulerOS-SA-2019-1436)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
	script_family( "Huawei EulerOS Local Security Checks" );
	script_dependencies( "gb_huawei_euleros_consolidation.sc" );
	script_mandatory_keys( "ssh/login/euleros", "ssh/login/rpms",  "ssh/login/release=EULEROSVIRT\\-3\\.0\\.1\\.0" );
	script_xref( name: "Advisory-ID", value: "EulerOS-SA-2019-1436" );
	script_xref( name: "URL", value: "https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2019-1436" );
	script_tag( name: "summary", value: "The remote host is missing an update for the Huawei EulerOS 'net-snmp' package(s) announced via the EulerOS-SA-2019-1436 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "It was discovered that the snmp_pdu_parse() mishandles error codes and is vulnerable to a heap corruption within the parsing of the PDU prior to the authentication process. A remote, unauthenticated attacker could use this flaw to crash snmpd or, potentially, execute arbitrary code on the system with the privileges of the user running snmpd.(CVE-2018-1000116)

snmp_oid_compare in snmplib/snmp_api.c in Net-SNMP before 5.8 has a NULL Pointer Exception bug that can be used by an unauthenticated attacker to remotely cause the instance to crash via a crafted UDP packet, resulting in Denial of Service.(CVE-2018-18066)

It was discovered that the snmp_pdu_parse() function could leave incompletely parsed varBind variables in the list of variables. A remote, unauthenticated attacker could use this flaw to crash snmpd or, potentially, execute arbitrary code on the system with the privileges of the user running snmpd.(CVE-2015-5621)" );
	script_tag( name: "affected", value: "'net-snmp' package(s) on Huawei EulerOS Virtualization 3.0.1.0." );
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
if(release == "EULEROSVIRT-3.0.1.0"){
	if(!isnull( res = isrpmvuln( pkg: "net-snmp", rpm: "net-snmp~5.7.2~33.2.h1", rls: "EULEROSVIRT-3.0.1.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "net-snmp-agent-libs", rpm: "net-snmp-agent-libs~5.7.2~33.2.h1", rls: "EULEROSVIRT-3.0.1.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "net-snmp-libs", rpm: "net-snmp-libs~5.7.2~33.2.h1", rls: "EULEROSVIRT-3.0.1.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "net-snmp-utils", rpm: "net-snmp-utils~5.7.2~33.2.h1", rls: "EULEROSVIRT-3.0.1.0" ) )){
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

