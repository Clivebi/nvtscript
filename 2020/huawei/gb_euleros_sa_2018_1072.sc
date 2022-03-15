if(description){
	script_oid( "1.3.6.1.4.1.25623.1.1.2.2018.1072" );
	script_cve_id( "CVE-2018-5732", "CVE-2018-5733" );
	script_tag( name: "creation_date", value: "2020-01-23 11:11:46 +0000 (Thu, 23 Jan 2020)" );
	script_version( "2021-07-22T02:24:02+0000" );
	script_tag( name: "last_modification", value: "2021-07-22 02:24:02 +0000 (Thu, 22 Jul 2021)" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-01-09 21:14:00 +0000 (Thu, 09 Jan 2020)" );
	script_name( "Huawei EulerOS: Security Advisory for dhcp (EulerOS-SA-2018-1072)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
	script_family( "Huawei EulerOS Local Security Checks" );
	script_dependencies( "gb_huawei_euleros_consolidation.sc" );
	script_mandatory_keys( "ssh/login/euleros", "ssh/login/rpms",  "ssh/login/release=EULEROS\\-2\\.0SP1" );
	script_xref( name: "Advisory-ID", value: "EulerOS-SA-2018-1072" );
	script_xref( name: "URL", value: "https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2018-1072" );
	script_tag( name: "summary", value: "The remote host is missing an update for the Huawei EulerOS 'dhcp' package(s) announced via the EulerOS-SA-2018-1072 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "An out-of-bound memory access flaw was found in the way dhclient processed a DHCP response packet. A malicious DHCP server could potentially use this flaw to crash dhclient processes running on DHCP client machines via a crafted DHCP response packet.(CVE-2018-5732)

A denial of service flaw was found in the way dhcpd handled reference counting when processing client requests. A malicious DHCP client could use this flaw to trigger a reference count overflow on the server side, potentially causing dhcpd to crash, by sending large amounts of traffic.(CVE-2018-5733)" );
	script_tag( name: "affected", value: "'dhcp' package(s) on Huawei EulerOS V2.0SP1." );
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
	if(!isnull( res = isrpmvuln( pkg: "dhclient", rpm: "dhclient~4.2.5~58.3.h2", rls: "EULEROS-2.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "dhcp", rpm: "dhcp~4.2.5~58.3.h2", rls: "EULEROS-2.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "dhcp-common", rpm: "dhcp-common~4.2.5~58.3.h2", rls: "EULEROS-2.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "dhcp-libs", rpm: "dhcp-libs~4.2.5~58.3.h2", rls: "EULEROS-2.0SP1" ) )){
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

