if(description){
	script_oid( "1.3.6.1.4.1.25623.1.1.2.2020.1457" );
	script_cve_id( "CVE-2015-5146", "CVE-2015-7973", "CVE-2018-7183", "CVE-2018-7184", "CVE-2019-8936" );
	script_tag( name: "creation_date", value: "2020-04-16 05:55:39 +0000 (Thu, 16 Apr 2020)" );
	script_version( "2021-07-22T02:24:02+0000" );
	script_tag( name: "last_modification", value: "2021-07-22 02:24:02 +0000 (Thu, 22 Jul 2021)" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-07-20 23:15:00 +0000 (Tue, 20 Jul 2021)" );
	script_name( "Huawei EulerOS: Security Advisory for ntp (EulerOS-SA-2020-1457)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
	script_family( "Huawei EulerOS Local Security Checks" );
	script_dependencies( "gb_huawei_euleros_consolidation.sc" );
	script_mandatory_keys( "ssh/login/euleros", "ssh/login/rpms",  "ssh/login/release=EULEROSVIRT\\-3\\.0\\.2\\.2" );
	script_xref( name: "Advisory-ID", value: "EulerOS-SA-2020-1457" );
	script_xref( name: "URL", value: "https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2020-1457" );
	script_tag( name: "summary", value: "The remote host is missing an update for the Huawei EulerOS 'ntp' package(s) announced via the EulerOS-SA-2020-1457 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "NTP through 4.2.8p12 has a NULL Pointer Dereference.(CVE-2019-8936)

ntpd in ntp 4.2.8p4 before 4.2.8p11 drops bad packets before updating the 'received' timestamp, which allows remote attackers to cause a denial of service (disruption) by sending a packet with a zero-origin timestamp causing the association to reset and setting the contents of the packet as the most recent timestamp. This issue is a result of an incomplete fix for CVE-2015-7704.(CVE-2018-7184)

Buffer overflow in the decodearr function in ntpq in ntp 4.2.8p6 through 4.2.8p10 allows remote attackers to execute arbitrary code by leveraging an ntpq query and sending a response with a crafted array.(CVE-2018-7183)

NTP before 4.2.8p6 and 4.3.x before 4.3.90, when configured in broadcast mode, allows man-in-the-middle attackers to conduct replay attacks by sniffing the network.(CVE-2015-7973)

ntpd in ntp before 4.2.8p3 with remote configuration enabled allows remote authenticated users with knowledge of the configuration password and access to a computer entrusted to perform remote configuration to cause a denial of service (service crash) via a NULL byte in a crafted configuration directive packet.(CVE-2015-5146)" );
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
	if(!isnull( res = isrpmvuln( pkg: "ntp", rpm: "ntp~4.2.6p5~28.h12.eulerosv2r7", rls: "EULEROSVIRT-3.0.2.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "ntpdate", rpm: "ntpdate~4.2.6p5~28.h12.eulerosv2r7", rls: "EULEROSVIRT-3.0.2.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "sntp", rpm: "sntp~4.2.6p5~28.h12.eulerosv2r7", rls: "EULEROSVIRT-3.0.2.2" ) )){
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

