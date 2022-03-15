if(description){
	script_oid( "1.3.6.1.4.1.25623.1.1.2.2021.1042" );
	script_cve_id( "CVE-2017-0381", "CVE-2017-7555" );
	script_tag( name: "creation_date", value: "2021-01-08 21:54:21 +0000 (Fri, 08 Jan 2021)" );
	script_version( "2021-07-22T02:24:02+0000" );
	script_tag( name: "last_modification", value: "2021-07-22 02:24:02 +0000 (Thu, 22 Jul 2021)" );
	script_tag( name: "cvss_base", value: "9.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:C/I:C/A:C" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2017-12-09 02:29:00 +0000 (Sat, 09 Dec 2017)" );
	script_name( "Huawei EulerOS: Security Advisory for augeas (EulerOS-SA-2021-1042)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "Huawei EulerOS Local Security Checks" );
	script_dependencies( "gb_huawei_euleros_consolidation.sc" );
	script_mandatory_keys( "ssh/login/euleros", "ssh/login/rpms",  "ssh/login/release=EULEROSVIRTARM64\\-3\\.0\\.2\\.0" );
	script_xref( name: "Advisory-ID", value: "EulerOS-SA-2021-1042" );
	script_xref( name: "URL", value: "https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2021-1042" );
	script_tag( name: "summary", value: "The remote host is missing an update for the Huawei EulerOS 'augeas' package(s) announced via the EulerOS-SA-2021-1042 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "An information disclosure vulnerability in silk/NLSF_stabilize.c in libopus in Mediaserver could enable a local malicious application to access data outside of its permission levels. This issue is rated as Moderate because it could be used to access sensitive data without permission. Product: Android. Versions: 5.0.2, 5.1.1, 6.0, 6.0.1, 7.0, 7.1. Android ID: A-31607432.(CVE-2017-0381)

Augeas versions up to and including 1.8.0 are vulnerable to heap-based buffer overflow due to improper handling of escaped strings. Attacker could send crafted strings that would cause the application using augeas to copy past the end of a buffer, leading to a crash or possible code execution.(CVE-2017-7555)" );
	script_tag( name: "affected", value: "'augeas' package(s) on Huawei EulerOS Virtualization for ARM 64 3.0.2.0." );
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
	if(!isnull( res = isrpmvuln( pkg: "augeas-libs", rpm: "augeas-libs~1.4.0~5.3", rls: "EULEROSVIRTARM64-3.0.2.0" ) )){
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

