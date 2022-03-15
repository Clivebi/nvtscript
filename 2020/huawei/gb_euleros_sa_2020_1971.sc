if(description){
	script_oid( "1.3.6.1.4.1.25623.1.1.2.2020.1971" );
	script_cve_id( "CVE-2020-12662", "CVE-2020-12663" );
	script_tag( name: "creation_date", value: "2020-09-08 08:07:55 +0000 (Tue, 08 Sep 2020)" );
	script_version( "2021-07-22T02:24:02+0000" );
	script_tag( name: "last_modification", value: "2021-07-22 02:24:02 +0000 (Thu, 22 Jul 2021)" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-02-17 21:00:00 +0000 (Wed, 17 Feb 2021)" );
	script_name( "Huawei EulerOS: Security Advisory for unbound (EulerOS-SA-2020-1971)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
	script_family( "Huawei EulerOS Local Security Checks" );
	script_dependencies( "gb_huawei_euleros_consolidation.sc" );
	script_mandatory_keys( "ssh/login/euleros", "ssh/login/rpms",  "ssh/login/release=EULEROSVIRTARM64\\-3\\.0\\.2\\.0" );
	script_xref( name: "Advisory-ID", value: "EulerOS-SA-2020-1971" );
	script_xref( name: "URL", value: "https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2020-1971" );
	script_tag( name: "summary", value: "The remote host is missing an update for the Huawei EulerOS 'unbound' package(s) announced via the EulerOS-SA-2020-1971 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "A flaw was found in unbound in versions prior to 1.10.1. An infinite loop can be created when malformed DNS answers are received from upstream servers. The highest threat from this vulnerability is to system availability.(CVE-2020-12663)

A network amplification vulnerability was found in Unbound, in the way it processes delegation messages from one authoritative zone to another. This flaw allows an attacker to cause a denial of service or be part of an attack against another DNS server when Unbound is deployed as a recursive resolver or authoritative name server.(CVE-2020-12662)" );
	script_tag( name: "affected", value: "'unbound' package(s) on Huawei EulerOS Virtualization for ARM 64 3.0.2.0." );
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
	if(!isnull( res = isrpmvuln( pkg: "unbound-libs", rpm: "unbound-libs~1.6.6~1.h3", rls: "EULEROSVIRTARM64-3.0.2.0" ) )){
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

