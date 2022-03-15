CPE = "cpe:/a:jenkins:jenkins";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.808277" );
	script_version( "2021-03-26T13:22:13+0000" );
	script_cve_id( "CVE-2011-4344" );
	script_bugtraq_id( 52384 );
	script_tag( name: "cvss_base", value: "2.6" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:H/Au:N/C:N/I:P/A:N" );
	script_tag( name: "last_modification", value: "2021-03-26 13:22:13 +0000 (Fri, 26 Mar 2021)" );
	script_tag( name: "creation_date", value: "2016-08-04 13:00:09 +0530 (Thu, 04 Aug 2016)" );
	script_name( "Jenkins Winstone Servlet Cross Site Scripting Vulnerability (Nov 2011) - Linux" );
	script_tag( name: "summary", value: "This host is installed with Jenkins and is prone
  to a cross-site scripting vulnerability." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "The flaw is due to an insufficient input
  validation error in 'winstone' servlet container that Jenkins runs in when
  running in standalone mode." );
	script_tag( name: "impact", value: "Successful exploitation will allow remote
  attackers to embed malicious JavaScript into pages generated by Jenkins." );
	script_tag( name: "affected", value: "Jenkins main line prior to 1.438, Jenkins LTS prior to 1.409.3." );
	script_tag( name: "solution", value: "Jenkins main line users should update to 1.438,
  Jenkins LTS users should update to 1.409.3." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "remote_banner_unreliable" );
	script_xref( name: "URL", value: "https://jenkins.io/security/advisory/2011-11-08/" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2016 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "gb_jenkins_consolidation.sc", "os_detection.sc" );
	script_mandatory_keys( "jenkins/detected", "Host/runs_unixoide" );
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
	if(version_is_less( version: version, test_version: "1.409.3" )){
		vuln = TRUE;
		fix = "1.409.3";
	}
}
else {
	if(version_is_less( version: version, test_version: "1.438" )){
		vuln = TRUE;
		fix = "1.438";
	}
}
if(vuln){
	report = report_fixed_ver( installed_version: version, fixed_version: fix, install_path: location );
	security_message( port: port, data: report, proto: proto );
	exit( 0 );
}
exit( 99 );
