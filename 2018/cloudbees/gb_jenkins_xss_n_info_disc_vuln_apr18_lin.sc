CPE = "cpe:/a:jenkins:jenkins";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.813316" );
	script_version( "2021-09-29T12:07:39+0000" );
	script_cve_id( "CVE-2018-1000169", "CVE-2018-1000170" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:N/A:N" );
	script_tag( name: "last_modification", value: "2021-09-29 12:07:39 +0000 (Wed, 29 Sep 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-07-31 03:15:00 +0000 (Wed, 31 Jul 2019)" );
	script_tag( name: "creation_date", value: "2018-04-23 16:40:26 +0530 (Mon, 23 Apr 2018)" );
	script_tag( name: "qod_type", value: "remote_banner_unreliable" );
	script_name( "Jenkins Multiple Vulnerabilities (Apr 2018) - Linux" );
	script_tag( name: "summary", value: "Jenkins is prone to multiple vulnerabilities." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "Multiple flaws are due to:

  - Some JavaScript confirmation dialogs included the item name in an unsafe
    manner.

  - The Jenkins CLI send different error responses for commands with view and
    agent arguments depending on the existence of the specified views or agents
    to unauthorized users." );
	script_tag( name: "impact", value: "Successful exploitation will allow remote
  attackers to execute a script on victim's Web browser within the security
  context of the hosting Web site and also disclose sensitive information." );
	script_tag( name: "affected", value: "Jenkins 2.115 and older, LTS 2.107.1 and older." );
	script_tag( name: "solution", value: "Update to Jenkins weekly to 2.116 or
  later, Jenkins LTS to 2.107.2 or later. Please see the references for more information." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "URL", value: "https://jenkins.io/security/advisory/2018-04-11/" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH" );
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
	if(version_is_less( version: version, test_version: "2.107.2" )){
		fix = "2.107.2";
	}
}
else {
	if(version_is_less( version: version, test_version: "2.116" )){
		fix = "2.116";
	}
}
if(fix){
	report = report_fixed_ver( installed_version: version, fixed_version: fix, install_path: location );
	security_message( port: port, data: report, proto: proto );
	exit( 0 );
}
exit( 99 );

