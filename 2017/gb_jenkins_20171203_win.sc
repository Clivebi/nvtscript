if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.113064" );
	script_version( "2021-09-16T08:01:42+0000" );
	script_tag( name: "last_modification", value: "2021-09-16 08:01:42 +0000 (Thu, 16 Sep 2021)" );
	script_tag( name: "creation_date", value: "2017-12-07 13:24:25 +0100 (Thu, 07 Dec 2017)" );
	script_tag( name: "cvss_base", value: "3.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:S/C:N/I:P/A:N" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:H/PR:N/UI:R/S:C/C:L/I:L/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2017-12-22 17:16:00 +0000 (Fri, 22 Dec 2017)" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_tag( name: "solution_type", value: "Workaround" );
	script_cve_id( "CVE-2017-17383" );
	script_name( "Jenkins 'CVE-2017-17383' XSS Vulnerability - Windows" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2017 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "gb_jenkins_consolidation.sc", "os_detection.sc" );
	script_mandatory_keys( "jenkins/detected", "Host/runs_windows" );
	script_tag( name: "summary", value: "Jenkins is prone to an XSS vulnerability." );
	script_tag( name: "vuldetect", value: "The script checks if the vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "An authenticated attacker can use a crafted tool name in a job configuration
  form to conduct XSS attacks." );
	script_tag( name: "impact", value: "Successful exploitation would allow an authenticated attacker to expose other
  users to malicious code." );
	script_tag( name: "affected", value: "Jenkins LTS 2.73.1 and prior, Jenkins 2.93 and prior." );
	script_tag( name: "solution", value: "Please refer to the vendor advisory for a workaround." );
	script_xref( name: "URL", value: "https://jenkins.io/security/advisory/2017-12-05/" );
	exit( 0 );
}
CPE = "cpe:/a:jenkins:jenkins";
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
	if(version_is_less_equal( version: version, test_version: "2.73.1" )){
		vuln = TRUE;
		fix = "See workaround in vendor advisory";
	}
}
else {
	if(version_is_less_equal( version: version, test_version: "2.93" )){
		vuln = TRUE;
		fix = "See workaround in vendor advisory";
	}
}
if(vuln){
	report = report_fixed_ver( installed_version: version, fixed_version: fix, install_path: location );
	security_message( port: port, data: report, proto: proto );
	exit( 0 );
}
exit( 99 );

