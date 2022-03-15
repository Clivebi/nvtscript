CPE = "cpe:/a:zohocorp:manageengine_opmanager";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.106093" );
	script_version( "2021-09-22T15:39:37+0000" );
	script_tag( name: "last_modification", value: "2021-09-22 15:39:37 +0000 (Wed, 22 Sep 2021)" );
	script_tag( name: "creation_date", value: "2016-06-06 16:31:30 +0700 (Mon, 06 Jun 2016)" );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:P/A:N" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_name( "ManageEngine OpManager < 12.0 Multiple Vulnerabilities" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2016 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "gb_manage_engine_opmanager_consolidation.sc" );
	script_mandatory_keys( "manageengine/opmanager/detected" );
	script_tag( name: "summary", value: "ManageEngine OpManager is prone to multiple vulnerabilities." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "Multiple XSS and CSRF vulnerabilities were found in ManageEngine
  OpManager." );
	script_tag( name: "impact", value: "Successful exploitation will allow remote attackers to execute
  arbitrary script code." );
	script_tag( name: "affected", value: "ManageEngine OpManager prior to version 12." );
	script_tag( name: "solution", value: "Update to version 12 or later." );
	script_xref( name: "URL", value: "http://seclists.org/bugtraq/2016/Jun/12" );
	exit( 0 );
}
require("host_details.inc.sc");
require("version_func.inc.sc");
if(isnull( port = get_app_port( cpe: CPE ) )){
	exit( 0 );
}
if(!infos = get_app_version_and_location( cpe: CPE, port: port, exit_no_version: TRUE )){
	exit( 0 );
}
version = infos["version"];
location = infos["location"];
if(version_is_less( version: version, test_version: "12" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "12", install_path: location );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

