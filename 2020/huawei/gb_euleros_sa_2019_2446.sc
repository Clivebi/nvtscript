if(description){
	script_oid( "1.3.6.1.4.1.25623.1.1.2.2019.2446" );
	script_cve_id( "CVE-2015-5146", "CVE-2015-7973", "CVE-2016-2517" );
	script_tag( name: "creation_date", value: "2020-01-23 12:58:04 +0000 (Thu, 23 Jan 2020)" );
	script_version( "2021-07-22T02:24:02+0000" );
	script_tag( name: "last_modification", value: "2021-07-22 02:24:02 +0000 (Thu, 22 Jul 2021)" );
	script_tag( name: "cvss_base", value: "5.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:P/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:L/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-04-26 17:42:00 +0000 (Mon, 26 Apr 2021)" );
	script_name( "Huawei EulerOS: Security Advisory for ntp (EulerOS-SA-2019-2446)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
	script_family( "Huawei EulerOS Local Security Checks" );
	script_dependencies( "gb_huawei_euleros_consolidation.sc" );
	script_mandatory_keys( "ssh/login/euleros", "ssh/login/rpms",  "ssh/login/release=EULEROS\\-2\\.0SP2" );
	script_xref( name: "Advisory-ID", value: "EulerOS-SA-2019-2446" );
	script_xref( name: "URL", value: "https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2019-2446" );
	script_tag( name: "summary", value: "The remote host is missing an update for the Huawei EulerOS 'ntp' package(s) announced via the EulerOS-SA-2019-2446 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "NTP before 4.2.8p7 and 4.3.x before 4.3.92 allows remote attackers to cause a denial of service (prevent subsequent authentication) by leveraging knowledge of the controlkey or requestkey and sending a crafted packet to ntpd, which changes the value of trustedkey, controlkey, or requestkey. NOTE: this vulnerability exists because of a CVE-2016-2516 regression.(CVE-2016-2517)

NTP before 4.2.8p6 and 4.3.x before 4.3.90, when configured in broadcast mode, allows man-in-the-middle attackers to conduct replay attacks by sniffing the network.(CVE-2015-7973)

ntpd in ntp before 4.2.8p3 with remote configuration enabled allows remote authenticated users with knowledge of the configuration password and access to a computer entrusted to perform remote configuration to cause a denial of service (service crash) via a NULL byte in a crafted configuration directive packet.(CVE-2015-5146)" );
	script_tag( name: "affected", value: "'ntp' package(s) on Huawei EulerOS V2.0SP2." );
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
	if(!isnull( res = isrpmvuln( pkg: "ntp", rpm: "ntp~4.2.6p5~25.1.h21", rls: "EULEROS-2.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "ntpdate", rpm: "ntpdate~4.2.6p5~25.1.h21", rls: "EULEROS-2.0SP2" ) )){
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

