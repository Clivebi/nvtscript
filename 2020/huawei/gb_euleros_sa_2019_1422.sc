if(description){
	script_oid( "1.3.6.1.4.1.25623.1.1.2.2019.1422" );
	script_cve_id( "CVE-2017-13077", "CVE-2017-13078", "CVE-2017-13079", "CVE-2017-13080", "CVE-2017-13081", "CVE-2017-13082", "CVE-2017-13086", "CVE-2017-13087", "CVE-2017-13088", "CVE-2018-14526" );
	script_tag( name: "creation_date", value: "2020-01-23 11:44:21 +0000 (Thu, 23 Jan 2020)" );
	script_version( "2021-07-22T02:24:02+0000" );
	script_tag( name: "last_modification", value: "2021-07-22 02:24:02 +0000 (Thu, 22 Jul 2021)" );
	script_tag( name: "cvss_base", value: "5.8" );
	script_tag( name: "cvss_base_vector", value: "AV:A/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:A/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-10-03 00:03:00 +0000 (Thu, 03 Oct 2019)" );
	script_name( "Huawei EulerOS: Security Advisory for wpa_supplicant (EulerOS-SA-2019-1422)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
	script_family( "Huawei EulerOS Local Security Checks" );
	script_dependencies( "gb_huawei_euleros_consolidation.sc" );
	script_mandatory_keys( "ssh/login/euleros", "ssh/login/rpms",  "ssh/login/release=EULEROSVIRT\\-3\\.0\\.1\\.0" );
	script_xref( name: "Advisory-ID", value: "EulerOS-SA-2019-1422" );
	script_xref( name: "URL", value: "https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2019-1422" );
	script_tag( name: "summary", value: "The remote host is missing an update for the Huawei EulerOS 'wpa_supplicant' package(s) announced via the EulerOS-SA-2019-1422 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "Wi-Fi Protected Access (WPA and WPA2) that supports IEEE 802.11w allows reinstallation of the Integrity Group Temporal Key (IGTK) during the four-way handshake, allowing an attacker within radio range to spoof frames from access points to clients.(CVE-2017-13079)

Wi-Fi Protected Access (WPA and WPA2) that supports IEEE 802.11w allows reinstallation of the Integrity Group Temporal Key (IGTK) during the group key handshake, allowing an attacker within radio range to spoof frames from access points to clients.(CVE-2017-13081)

An issue was discovered in rsn_supp/wpa.c in wpa_supplicant 2.0 through 2.6. Under certain conditions, the integrity of EAPOL-Key messages is not checked, leading to a decryption oracle. An attacker within range of the Access Point and client can abuse the vulnerability to recover sensitive information.(CVE-2018-14526)

A new exploitation technique called key reinstallation attacks (KRACK) affecting WPA2 has been discovered. A remote attacker within Wi-Fi range could exploit this attack to decrypt Wi-Fi traffic or possibly inject forged Wi-Fi packets by reinstalling a previously used integrity group key (IGTK) during a Wireless Network Management (WNM) Sleep Mode handshake.(CVE-2017-13088)

A new exploitation technique called key reinstallation attacks (KRACK) affecting WPA2 has been discovered. A remote attacker within Wi-Fi range could exploit this attack to decrypt Wi-Fi traffic or possibly inject forged Wi-Fi packets by reinstalling a previously used group key (GTK) during a group key handshake.(CVE-2017-13080)

A new exploitation technique called key reinstallation attacks (KRACK) affecting WPA2 has been discovered. A remote attacker within Wi-Fi range could exploit this attack to decrypt Wi-Fi traffic or possibly inject forged Wi-Fi packets by reinstalling a previously used group key (GTK) during a Wireless Network Management (WNM) Sleep Mode handshake.(CVE-2017-13087)

A new exploitation technique called key reinstallation attacks (KRACKs) affecting WPA2 has been discovered. A remote attacker within Wi-Fi range could exploit this attack to decrypt Wi-Fi traffic or possibly inject forged Wi-Fi packets by reinstalling a previously used pairwise key (PTK-TK) during a 4-way handshake.(CVE-2017-13077)

A new exploitation technique called key reinstallation attacks (KRACK) affecting WPA2 has been discovered. A remote attacker within Wi-Fi range could exploit this attack to decrypt Wi-Fi traffic or possibly inject forged Wi-Fi packets by reinstalling a previously used group key (GTK) during a 4-way handshake.(CVE-2017-13078)

A new exploitation technique called key reinstallation attacks (KRACK) affecting WPA2 has been discovered. A remote attacker within Wi-Fi range could exploit this attack to decrypt Wi-Fi traffic or possibly inject forged Wi-Fi packets by reinstalling a previously used pairwise key (PTK-TK) by retransmitting Fast BSS Transition ... [Please see the references for more information on the vulnerabilities]" );
	script_tag( name: "affected", value: "'wpa_supplicant' package(s) on Huawei EulerOS Virtualization 3.0.1.0." );
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
	if(!isnull( res = isrpmvuln( pkg: "wpa_supplicant", rpm: "wpa_supplicant~2.6~9.h1.eulerosv2r7", rls: "EULEROSVIRT-3.0.1.0" ) )){
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

