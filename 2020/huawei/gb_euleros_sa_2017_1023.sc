if(description){
	script_oid( "1.3.6.1.4.1.25623.1.1.2.2017.1023" );
	script_cve_id( "CVE-2016-7426", "CVE-2016-7429", "CVE-2016-7433", "CVE-2016-9310", "CVE-2016-9311" );
	script_tag( name: "creation_date", value: "2020-01-23 10:44:21 +0000 (Thu, 23 Jan 2020)" );
	script_version( "2021-07-22T02:24:02+0000" );
	script_tag( name: "last_modification", value: "2021-07-22 02:24:02 +0000 (Thu, 22 Jul 2021)" );
	script_tag( name: "cvss_base", value: "7.1" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:N/A:C" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-06-18 18:14:00 +0000 (Thu, 18 Jun 2020)" );
	script_name( "Huawei EulerOS: Security Advisory for ntp (EulerOS-SA-2017-1023)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
	script_family( "Huawei EulerOS Local Security Checks" );
	script_dependencies( "gb_huawei_euleros_consolidation.sc" );
	script_mandatory_keys( "ssh/login/euleros", "ssh/login/rpms",  "ssh/login/release=EULEROS\\-2\\.0SP1" );
	script_xref( name: "Advisory-ID", value: "EulerOS-SA-2017-1023" );
	script_xref( name: "URL", value: "https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2017-1023" );
	script_tag( name: "summary", value: "The remote host is missing an update for the Huawei EulerOS 'ntp' package(s) announced via the EulerOS-SA-2017-1023 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "It was found that when ntp is configured with rate limiting for all associations the limits are also applied to responses received from its configured sources. A remote attacker who knows the sources can cause a denial of service by preventing ntpd from accepting valid responses from its sources. (CVE-2016-7426)

A flaw was found in the control mode functionality of ntpd. A remote attacker could send a crafted control mode packet which could lead to information disclosure or result in DDoS amplification attacks. (CVE-2016-9310)

 A flaw was found in the way ntpd implemented the trap service. A remote attacker could send a specially crafted packet to cause a null pointer dereference that will crash ntpd, resulting in a denial of service. (CVE-2016-9311)

A flaw was found in the way ntpd running on a host with multiple network interfaces handled certain server responses. A remote attacker could use this flaw which would cause ntpd to not synchronize with the source. (CVE-2016-7429)

A flaw was found in the way ntpd calculated the root delay. A remote attacker could send a specially-crafted spoofed packet to cause denial of service or in some special cases even crash. (CVE-2016-7433)" );
	script_tag( name: "affected", value: "'ntp' package(s) on Huawei EulerOS V2.0SP1." );
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
	if(!isnull( res = isrpmvuln( pkg: "ntp", rpm: "ntp~4.2.6p5~25.0.1.h1", rls: "EULEROS-2.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "ntpdate", rpm: "ntpdate~4.2.6p5~25.0.1.h1", rls: "EULEROS-2.0SP1" ) )){
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

