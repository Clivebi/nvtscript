if(description){
	script_oid( "1.3.6.1.4.1.25623.1.1.2.2021.1040" );
	script_cve_id( "CVE-2020-15861", "CVE-2020-15862" );
	script_tag( name: "creation_date", value: "2021-01-08 21:53:47 +0000 (Fri, 08 Jan 2021)" );
	script_version( "2021-07-22T02:24:02+0000" );
	script_tag( name: "last_modification", value: "2021-07-22 02:24:02 +0000 (Thu, 22 Jul 2021)" );
	script_tag( name: "cvss_base", value: "7.2" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:L/Au:N/C:C/I:C/A:C" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-09-04 11:15:00 +0000 (Fri, 04 Sep 2020)" );
	script_name( "Huawei EulerOS: Security Advisory for net-snmp (EulerOS-SA-2021-1040)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "Huawei EulerOS Local Security Checks" );
	script_dependencies( "gb_huawei_euleros_consolidation.sc" );
	script_mandatory_keys( "ssh/login/euleros", "ssh/login/rpms",  "ssh/login/release=EULEROSVIRTARM64\\-3\\.0\\.2\\.0" );
	script_xref( name: "Advisory-ID", value: "EulerOS-SA-2021-1040" );
	script_xref( name: "URL", value: "https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2021-1040" );
	script_tag( name: "summary", value: "The remote host is missing an update for the Huawei EulerOS 'net-snmp' package(s) announced via the EulerOS-SA-2021-1040 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "Net-SNMP through 5.7.3 has Improper Privilege Management because SNMP WRITE access to the EXTEND MIB provides the ability to run arbitrary commands as root.(CVE-2020-15862)

Net-SNMP through 5.7.3 allows Escalation of Privileges because of UNIX symbolic link (symlink) following.(CVE-2020-15861)" );
	script_tag( name: "affected", value: "'net-snmp' package(s) on Huawei EulerOS Virtualization for ARM 64 3.0.2.0." );
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
if(release == "EULEROSVIRTARM64-3.0.2.0"){
	if(!isnull( res = isrpmvuln( pkg: "net-snmp", rpm: "net-snmp~5.7.2~33.2.h6", rls: "EULEROSVIRTARM64-3.0.2.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "net-snmp-agent-libs", rpm: "net-snmp-agent-libs~5.7.2~33.2.h6", rls: "EULEROSVIRTARM64-3.0.2.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "net-snmp-libs", rpm: "net-snmp-libs~5.7.2~33.2.h6", rls: "EULEROSVIRTARM64-3.0.2.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "net-snmp-utils", rpm: "net-snmp-utils~5.7.2~33.2.h6", rls: "EULEROSVIRTARM64-3.0.2.0" ) )){
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
