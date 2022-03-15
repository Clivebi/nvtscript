if(description){
	script_oid( "1.3.6.1.4.1.25623.1.1.2.2021.1538" );
	script_cve_id( "CVE-2018-19787", "CVE-2020-27783" );
	script_tag( name: "creation_date", value: "2021-03-05 07:09:49 +0000 (Fri, 05 Mar 2021)" );
	script_version( "2021-07-22T02:24:02+0000" );
	script_tag( name: "last_modification", value: "2021-07-22 02:24:02 +0000 (Thu, 22 Jul 2021)" );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:P/A:N" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-11-26 21:15:00 +0000 (Thu, 26 Nov 2020)" );
	script_name( "Huawei EulerOS: Security Advisory for python-lxml (EulerOS-SA-2021-1538)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "Huawei EulerOS Local Security Checks" );
	script_dependencies( "gb_huawei_euleros_consolidation.sc" );
	script_mandatory_keys( "ssh/login/euleros", "ssh/login/rpms",  "ssh/login/release=EULEROSVIRTARM64\\-3\\.0\\.6\\.0" );
	script_xref( name: "Advisory-ID", value: "EulerOS-SA-2021-1538" );
	script_xref( name: "URL", value: "https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2021-1538" );
	script_tag( name: "summary", value: "The remote host is missing an update for the Huawei EulerOS 'python-lxml' package(s) announced via the EulerOS-SA-2021-1538 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "An issue was discovered in lxml before 4.2.5. lxml/html/clean.py in the lxml.html.clean module does not remove javascript: URLs that use escaping, allowing a remote attacker to conduct XSS attacks, as demonstrated by 'j a v a s c r i p t:' in Internet Explorer. This is a similar issue to CVE-2014-3146.(CVE-2018-19787)

A XSS vulnerability was discovered in python-lxml's clean module. The module's parser didn't properly imitate browsers, which caused different behaviors between the sanitizer and the user's page. A remote attacker could exploit this flaw to run arbitrary HTML/JS code.CVE-2020-27783)" );
	script_tag( name: "affected", value: "'python-lxml' package(s) on Huawei EulerOS Virtualization for ARM 64 3.0.6.0." );
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
if(release == "EULEROSVIRTARM64-3.0.6.0"){
	if(!isnull( res = isrpmvuln( pkg: "python2-lxml", rpm: "python2-lxml~4.2.3~2.h3.eulerosv2r8", rls: "EULEROSVIRTARM64-3.0.6.0" ) )){
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

