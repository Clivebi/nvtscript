CPE = "cpe:/a:jenkins:jenkins";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.807349" );
	script_version( "2021-08-10T15:24:26+0000" );
	script_cve_id( "CVE-2013-2034", "CVE-2013-2033", "CVE-2013-1808" );
	script_bugtraq_id( 59631, 59634, 58257 );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2021-08-10 15:24:26 +0000 (Tue, 10 Aug 2021)" );
	script_tag( name: "creation_date", value: "2016-07-14 13:00:47 +0530 (Thu, 14 Jul 2016)" );
	script_name( "Jenkins CSRF And XSS Vulnerabilities - Windows" );
	script_tag( name: "summary", value: "This host is installed with Jenkins and is
  prone to cross-site request forgery and cross-site scripting vulnerabilities." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "Multiple flaws exist due to:

  - A cross-site request forgery (CSRF) flaw in the Jenkins master, where an
    anonymous attacker can trick an administrator to execute arbitrary code on
    Jenkins master by having him open a specifically crafted attack URL.

  - The multiple input validation errors." );
	script_tag( name: "impact", value: "Successful exploitation will allow remote
  attackers to execute arbitrary code on Jenkins master by having him open a
  specifically crafted attack URL and to execute JavaScript in the browser of other users." );
	script_tag( name: "affected", value: "Jenkins main line prior to 1.514, Jenkins LTS prior to 1.509.1." );
	script_tag( name: "solution", value: "Jenkins main line users should update to 1.514,
  Jenkins LTS users should update to 1.509.1." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_xref( name: "URL", value: "https://jenkins.io/security/advisory/2013-05-02/" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2016 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "gb_jenkins_consolidation.sc", "os_detection.sc" );
	script_mandatory_keys( "jenkins/detected", "Host/runs_windows" );
	exit( 0 );
}
require("host_details.inc.sc");
require("version_func.inc.sc");
if(!port = get_app_port( cpe: CPE )){
	exit( 0 );
}
if(!infos = get_app_full( cpe: CPE, port: port, exit_no_version: TRUE )){
	exit( 0 );
}
version = infos["version"];
location = infos["location"];
proto = infos["proto"];
if( get_kb_item( "jenkins/" + port + "/is_lts" ) ){
	if(version_is_less( version: version, test_version: "1.509.1" )){
		vuln = TRUE;
		fix = "1.509.1";
	}
}
else {
	if(version_is_less( version: version, test_version: "1.514" )){
		vuln = TRUE;
		fix = "1.514";
	}
}
if(vuln){
	report = report_fixed_ver( installed_version: version, fixed_version: fix, install_path: location );
	security_message( port: port, data: report, proto: proto );
	exit( 0 );
}
exit( 99 );

