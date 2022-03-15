if(description){
	script_oid( "1.3.6.1.4.1.25623.1.1.2.2021.1458" );
	script_cve_id( "CVE-2020-8622", "CVE-2020-8623" );
	script_tag( name: "creation_date", value: "2021-03-05 07:07:08 +0000 (Fri, 05 Mar 2021)" );
	script_version( "2021-07-22T02:24:02+0000" );
	script_tag( name: "last_modification", value: "2021-07-22 02:24:02 +0000 (Thu, 22 Jul 2021)" );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:N/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-10-20 12:15:00 +0000 (Tue, 20 Oct 2020)" );
	script_name( "Huawei EulerOS: Security Advisory for bind (EulerOS-SA-2021-1458)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "Huawei EulerOS Local Security Checks" );
	script_dependencies( "gb_huawei_euleros_consolidation.sc" );
	script_mandatory_keys( "ssh/login/euleros", "ssh/login/rpms",  "ssh/login/release=EULEROSVIRT\\-3\\.0\\.6\\.6" );
	script_xref( name: "Advisory-ID", value: "EulerOS-SA-2021-1458" );
	script_xref( name: "URL", value: "https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2021-1458" );
	script_tag( name: "summary", value: "The remote host is missing an update for the Huawei EulerOS 'bind' package(s) announced via the EulerOS-SA-2021-1458 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "In BIND 9.0.0 -> 9.11.21, 9.12.0 -> 9.16.5, 9.17.0 -> 9.17.3, also affects 9.9.3-S1 -> 9.11.21-S1 of the BIND 9 Supported Preview Edition, An attacker on the network path for a TSIG-signed request, or operating the server receiving the TSIG-signed request, could send a truncated response to that request, triggering an assertion failure, causing the server to exit. Alternately, an off-path attacker would have to correctly guess when a TSIG-signed request was sent, along with other characteristics of the packet and message, and spoof a truncated response to trigger an assertion failure, causing the server to exit.(CVE-2020-8622)

In BIND 9.10.0 -> 9.11.21, 9.12.0 -> 9.16.5, 9.17.0 -> 9.17.3, also affects 9.10.5-S1 -> 9.11.21-S1 of the BIND 9 Supported Preview Edition, An attacker that can reach a vulnerable system with a specially crafted query packet can trigger a crash. To be vulnerable, the system must: * be running BIND that was built with '--enable-native-pkcs11' * be signing one or more zones with an RSA key * be able to receive queries from a possible attacker(CVE-2020-8623)" );
	script_tag( name: "affected", value: "'bind' package(s) on Huawei EulerOS Virtualization 3.0.6.6." );
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
if(release == "EULEROSVIRT-3.0.6.6"){
	if(!isnull( res = isrpmvuln( pkg: "bind", rpm: "bind~9.9.4~61.1.h13.eulerosv2r7", rls: "EULEROSVIRT-3.0.6.6" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "bind-chroot", rpm: "bind-chroot~9.9.4~61.1.h13.eulerosv2r7", rls: "EULEROSVIRT-3.0.6.6" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "bind-libs", rpm: "bind-libs~9.9.4~61.1.h13.eulerosv2r7", rls: "EULEROSVIRT-3.0.6.6" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "bind-libs-lite", rpm: "bind-libs-lite~9.9.4~61.1.h13.eulerosv2r7", rls: "EULEROSVIRT-3.0.6.6" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "bind-license", rpm: "bind-license~9.9.4~61.1.h13.eulerosv2r7", rls: "EULEROSVIRT-3.0.6.6" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "bind-pkcs11", rpm: "bind-pkcs11~9.9.4~61.1.h13.eulerosv2r7", rls: "EULEROSVIRT-3.0.6.6" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "bind-pkcs11-libs", rpm: "bind-pkcs11-libs~9.9.4~61.1.h13.eulerosv2r7", rls: "EULEROSVIRT-3.0.6.6" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "bind-pkcs11-utils", rpm: "bind-pkcs11-utils~9.9.4~61.1.h13.eulerosv2r7", rls: "EULEROSVIRT-3.0.6.6" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "bind-utils", rpm: "bind-utils~9.9.4~61.1.h13.eulerosv2r7", rls: "EULEROSVIRT-3.0.6.6" ) )){
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

