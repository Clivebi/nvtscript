if(description){
	script_oid( "1.3.6.1.4.1.25623.1.1.2.2020.1722" );
	script_cve_id( "CVE-2018-1000135" );
	script_tag( name: "creation_date", value: "2020-07-03 06:18:47 +0000 (Fri, 03 Jul 2020)" );
	script_version( "2021-07-22T02:24:02+0000" );
	script_tag( name: "last_modification", value: "2021-07-22 02:24:02 +0000 (Thu, 22 Jul 2021)" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:N/A:N" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-06-03 12:29:00 +0000 (Mon, 03 Jun 2019)" );
	script_name( "Huawei EulerOS: Security Advisory for NetworkManager (EulerOS-SA-2020-1722)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
	script_family( "Huawei EulerOS Local Security Checks" );
	script_dependencies( "gb_huawei_euleros_consolidation.sc" );
	script_mandatory_keys( "ssh/login/euleros", "ssh/login/rpms",  "ssh/login/release=EULEROSVIRT\\-3\\.0\\.6\\.0" );
	script_xref( name: "Advisory-ID", value: "EulerOS-SA-2020-1722" );
	script_xref( name: "URL", value: "https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2020-1722" );
	script_tag( name: "summary", value: "The remote host is missing an update for the Huawei EulerOS 'NetworkManager' package(s) announced via the EulerOS-SA-2020-1722 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "An information exposure vulnerability has been found in NetworkManager when dnsmasq is used in DNS processing mode. An attacker in control of a DNS server could receive DNS queries even though a Virtual Private Network (VPN) was configured on the vulnerable machine.(CVE-2018-1000135)" );
	script_tag( name: "affected", value: "'NetworkManager' package(s) on Huawei EulerOS Virtualization 3.0.6.0." );
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
if(release == "EULEROSVIRT-3.0.6.0"){
	if(!isnull( res = isrpmvuln( pkg: "NetworkManager", rpm: "NetworkManager~1.10.2~16.h5.eulerosv2r7", rls: "EULEROSVIRT-3.0.6.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "NetworkManager-config-server", rpm: "NetworkManager-config-server~1.10.2~16.h5.eulerosv2r7", rls: "EULEROSVIRT-3.0.6.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "NetworkManager-glib", rpm: "NetworkManager-glib~1.10.2~16.h5.eulerosv2r7", rls: "EULEROSVIRT-3.0.6.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "NetworkManager-libnm", rpm: "NetworkManager-libnm~1.10.2~16.h5.eulerosv2r7", rls: "EULEROSVIRT-3.0.6.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "NetworkManager-team", rpm: "NetworkManager-team~1.10.2~16.h5.eulerosv2r7", rls: "EULEROSVIRT-3.0.6.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "NetworkManager-tui", rpm: "NetworkManager-tui~1.10.2~16.h5.eulerosv2r7", rls: "EULEROSVIRT-3.0.6.0" ) )){
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

