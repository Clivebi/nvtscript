if(description){
	script_oid( "1.3.6.1.4.1.25623.1.1.2.2021.2151" );
	script_cve_id( "CVE-2020-11868", "CVE-2020-13817" );
	script_tag( name: "creation_date", value: "2021-07-07 08:44:02 +0000 (Wed, 07 Jul 2021)" );
	script_version( "2021-07-22T02:24:02+0000" );
	script_tag( name: "last_modification", value: "2021-07-22 02:24:02 +0000 (Thu, 22 Jul 2021)" );
	script_tag( name: "cvss_base", value: "5.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:P/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-07-20 23:15:00 +0000 (Tue, 20 Jul 2021)" );
	script_name( "Huawei EulerOS: Security Advisory for ntp (EulerOS-SA-2021-2151)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "Huawei EulerOS Local Security Checks" );
	script_dependencies( "gb_huawei_euleros_consolidation.sc" );
	script_mandatory_keys( "ssh/login/euleros", "ssh/login/rpms",  "ssh/login/release=EULEROSVIRT\\-3\\.0\\.2\\.2" );
	script_xref( name: "Advisory-ID", value: "EulerOS-SA-2021-2151" );
	script_xref( name: "URL", value: "https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2021-2151" );
	script_tag( name: "summary", value: "The remote host is missing an update for the Huawei EulerOS 'ntp' package(s) announced via the EulerOS-SA-2021-2151 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "ntpd in ntp before 4.2.8p14 and 4.3.x before 4.3.100 allows an off-path attacker to block unauthenticated synchronization via a server mode packet with a spoofed source IP address, because transmissions are rescheduled even when a packet lacks a valid origin timestamp.(CVE-2020-11868)

ntpd in ntp before 4.2.8p14 and 4.3.x before 4.3.100 allows remote attackers to cause a denial of service (daemon exit or system time change) by predicting transmit timestamps for use in spoofed packets. The victim must be relying on unauthenticated IPv4 time sources. There must be an off-path attacker who can query time from the victim's ntpd instance.(CVE-2020-13817)" );
	script_tag( name: "affected", value: "'ntp' package(s) on Huawei EulerOS Virtualization 3.0.2.2." );
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
if(release == "EULEROSVIRT-3.0.2.2"){
	if(!isnull( res = isrpmvuln( pkg: "ntp", rpm: "ntp~4.2.6p5~28.h20.eulerosv2r7", rls: "EULEROSVIRT-3.0.2.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "ntpdate", rpm: "ntpdate~4.2.6p5~28.h20.eulerosv2r7", rls: "EULEROSVIRT-3.0.2.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "sntp", rpm: "sntp~4.2.6p5~28.h20.eulerosv2r7", rls: "EULEROSVIRT-3.0.2.2" ) )){
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

