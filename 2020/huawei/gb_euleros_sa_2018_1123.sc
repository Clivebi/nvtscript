if(description){
	script_oid( "1.3.6.1.4.1.25623.1.1.2.2018.1123" );
	script_cve_id( "CVE-2015-8605", "CVE-2018-1111" );
	script_tag( name: "creation_date", value: "2020-01-23 11:13:33 +0000 (Thu, 23 Jan 2020)" );
	script_version( "2021-07-22T02:24:02+0000" );
	script_tag( name: "last_modification", value: "2021-07-22 02:24:02 +0000 (Thu, 22 Jul 2021)" );
	script_tag( name: "cvss_base", value: "7.9" );
	script_tag( name: "cvss_base_vector", value: "AV:A/AC:M/Au:N/C:C/I:C/A:C" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:A/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-10-03 00:03:00 +0000 (Thu, 03 Oct 2019)" );
	script_name( "Huawei EulerOS: Security Advisory for dhcp (EulerOS-SA-2018-1123)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
	script_family( "Huawei EulerOS Local Security Checks" );
	script_dependencies( "gb_huawei_euleros_consolidation.sc" );
	script_mandatory_keys( "ssh/login/euleros", "ssh/login/rpms",  "ssh/login/release=EULEROS\\-2\\.0SP2" );
	script_xref( name: "Advisory-ID", value: "EulerOS-SA-2018-1123" );
	script_xref( name: "URL", value: "https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2018-1123" );
	script_tag( name: "summary", value: "The remote host is missing an update for the Huawei EulerOS 'dhcp' package(s) announced via the EulerOS-SA-2018-1123 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "A command injection flaw was found in the NetworkManager integration script included in the DHCP client packages in Red Hat Enterprise Linux. A malicious DHCP server, or an attacker on the local network able to spoof DHCP responses, could use this flaw to execute arbitrary commands with root privileges on systems using NetworkManager and configured to obtain network configuration using the DHCP protocol.(CVE-2018-1111)

ISC DHCP 4.x before 4.1-ESV-R12-P1, 4.2.x, and 4.3.x before 4.3.3-P1 allows remote attackers to cause a denial of service (application crash) via an invalid length field in a UDP IPv4 packet.(CVE-2015-8605)" );
	script_tag( name: "affected", value: "'dhcp' package(s) on Huawei EulerOS V2.0SP2." );
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
	if(!isnull( res = isrpmvuln( pkg: "dhclient", rpm: "dhclient~4.2.5~68.1.h2", rls: "EULEROS-2.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "dhcp", rpm: "dhcp~4.2.5~68.1.h2", rls: "EULEROS-2.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "dhcp-common", rpm: "dhcp-common~4.2.5~68.1.h2", rls: "EULEROS-2.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "dhcp-libs", rpm: "dhcp-libs~4.2.5~68.1.h2", rls: "EULEROS-2.0SP2" ) )){
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

