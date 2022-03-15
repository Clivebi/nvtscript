if(description){
	script_oid( "1.3.6.1.4.1.25623.1.1.2.2021.1450" );
	script_cve_id( "CVE-2020-25613" );
	script_tag( name: "creation_date", value: "2021-03-05 07:06:42 +0000 (Fri, 05 Mar 2021)" );
	script_version( "2021-07-22T02:24:02+0000" );
	script_tag( name: "last_modification", value: "2021-07-22 02:24:02 +0000 (Thu, 22 Jul 2021)" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:P/A:N" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-01-15 11:15:00 +0000 (Fri, 15 Jan 2021)" );
	script_name( "Huawei EulerOS: Security Advisory for ruby (EulerOS-SA-2021-1450)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "Huawei EulerOS Local Security Checks" );
	script_dependencies( "gb_huawei_euleros_consolidation.sc" );
	script_mandatory_keys( "ssh/login/euleros", "ssh/login/rpms",  "ssh/login/release=EULEROSVIRT\\-3\\.0\\.2\\.6" );
	script_xref( name: "Advisory-ID", value: "EulerOS-SA-2021-1450" );
	script_xref( name: "URL", value: "https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2021-1450" );
	script_tag( name: "summary", value: "The remote host is missing an update for the Huawei EulerOS 'ruby' package(s) announced via the EulerOS-SA-2021-1450 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "An issue was discovered in Ruby through 2.5.8, 2.6.x through 2.6.6, and 2.7.x through 2.7.1. WEBrick, a simple HTTP server bundled with Ruby, had not checked the transfer-encoding header value rigorously. An attacker may potentially exploit this issue to bypass a reverse proxy (which also has a poor header check), which may lead to an HTTP Request Smuggling attack." );
	script_tag( name: "affected", value: "'ruby' package(s) on Huawei EulerOS Virtualization 3.0.2.6." );
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
if(release == "EULEROSVIRT-3.0.2.6"){
	if(!isnull( res = isrpmvuln( pkg: "ruby", rpm: "ruby~2.0.0.648~33.h28.eulerosv2r7", rls: "EULEROSVIRT-3.0.2.6" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "ruby-irb", rpm: "ruby-irb~2.0.0.648~33.h28.eulerosv2r7", rls: "EULEROSVIRT-3.0.2.6" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "ruby-libs", rpm: "ruby-libs~2.0.0.648~33.h28.eulerosv2r7", rls: "EULEROSVIRT-3.0.2.6" ) )){
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

