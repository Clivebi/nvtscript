if(description){
	script_oid( "1.3.6.1.4.1.25623.1.1.2.2019.1725" );
	script_cve_id( "CVE-2019-1000019", "CVE-2019-1000020" );
	script_tag( name: "creation_date", value: "2020-01-23 12:21:03 +0000 (Thu, 23 Jan 2020)" );
	script_version( "2021-07-22T02:24:02+0000" );
	script_tag( name: "last_modification", value: "2021-07-22 02:24:02 +0000 (Thu, 22 Jul 2021)" );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:N/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-11-06 01:15:00 +0000 (Wed, 06 Nov 2019)" );
	script_name( "Huawei EulerOS: Security Advisory for libarchive (EulerOS-SA-2019-1725)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
	script_family( "Huawei EulerOS Local Security Checks" );
	script_dependencies( "gb_huawei_euleros_consolidation.sc" );
	script_mandatory_keys( "ssh/login/euleros", "ssh/login/rpms",  "ssh/login/release=EULEROS\\-2\\.0SP2" );
	script_xref( name: "Advisory-ID", value: "EulerOS-SA-2019-1725" );
	script_xref( name: "URL", value: "https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2019-1725" );
	script_tag( name: "summary", value: "The remote host is missing an update for the Huawei EulerOS 'libarchive' package(s) announced via the EulerOS-SA-2019-1725 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "OpenEMR version 5.0.0 contains a Cross Site Scripting (XSS) vulnerability in open-flash-chart.swf and _posteddata.php that can result in . This vulnerability appears to have been fixed in 5.0.0 Patch 2 or higher.(CVE-2018-1000020)

OpenEMR version 5.0.0 contains a OS Command Injection vulnerability in fax_dispatch.php that can result in OS command injection by an authenticated attacker with any role. This vulnerability appears to have been fixed in 5.0.0 Patch 2 or higher.(CVE-2018-1000019)" );
	script_tag( name: "affected", value: "'libarchive' package(s) on Huawei EulerOS V2.0SP2." );
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
	if(!isnull( res = isrpmvuln( pkg: "libarchive", rpm: "libarchive~3.1.2~10.h1", rls: "EULEROS-2.0SP2" ) )){
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

