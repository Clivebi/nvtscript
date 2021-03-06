if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.113793" );
	script_version( "2021-08-26T09:01:14+0000" );
	script_tag( name: "last_modification", value: "2021-08-26 09:01:14 +0000 (Thu, 26 Aug 2021)" );
	script_tag( name: "creation_date", value: "2021-03-03 10:03:48 +0000 (Wed, 03 Mar 2021)" );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-03-18 20:13:00 +0000 (Thu, 18 Mar 2021)" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_tag( name: "solution_type", value: "NoneAvailable" );
	script_cve_id( "CVE-2021-27885" );
	script_name( "e107 <= 2.3.0 Authentication Bypass Vulnerability" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "e107_detect.sc" );
	script_mandatory_keys( "e107/installed" );
	script_tag( name: "summary", value: "e107 is prone to an authentication bypass vulnerability." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "The vulnerability exists due to the lack of
  an e_TOKEN protection mechanism." );
	script_tag( name: "impact", value: "Successful exploitation would allow an attacker
  to gain unauthorized access." );
	script_tag( name: "affected", value: "e107 through version 2.3.0." );
	script_tag( name: "solution", value: "No known solution is available as of 03rd March, 2021.
  Information regarding this issue will be updated once solution details are available." );
	exit( 0 );
}
CPE = "cpe:/a:e107:e107";
require("host_details.inc.sc");
require("version_func.inc.sc");
if(!port = get_app_port( cpe: CPE )){
	exit( 0 );
}
if(!infos = get_app_version_and_location( cpe: CPE, port: port, exit_no_version: TRUE )){
	exit( 0 );
}
version = infos["version"];
location = infos["location"];
if(version_is_less_equal( version: version, test_version: "2.3.0" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "None Available", install_path: location );
	security_message( data: report, port: port );
	exit( 0 );
}
exit( 99 );

