if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.107001" );
	script_tag( name: "cvss_base", value: "4.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:S/C:P/I:N/A:N" );
	script_version( "2020-05-07T12:00:48+0000" );
	script_tag( name: "last_modification", value: "2020-05-07 12:00:48 +0000 (Thu, 07 May 2020)" );
	script_tag( name: "creation_date", value: "2016-05-10 14:43:29 +0200 (Tue, 10 May 2016)" );
	script_tag( name: "qod_type", value: "remote_banner_unreliable" );
	script_name( "GLPI 0.92.0 SQL Injection Vulnerability" );
	script_category( ACT_GATHER_INFO );
	script_family( "Web application abuses" );
	script_copyright( "Copyright (C) 2016 Greenbone Networks GmbH" );
	script_dependencies( "gb_glpi_detect.sc" );
	script_mandatory_keys( "glpi/detected" );
	script_tag( name: "summary", value: "Detection of GLPI SQL Injection vulnerability." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "solution", value: "Update to version 0.90.3 or later." );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("host_details.inc.sc");
require("version_func.inc.sc");
CPE = "cpe:/a:glpi-project:glpi";
if(!port = get_app_port( cpe: CPE )){
	exit( 0 );
}
if(!vers = get_app_version( cpe: CPE, port: port )){
	exit( 0 );
}
if(version_is_less( version: vers, test_version: "0.90.3" )){
	report = report_fixed_ver( installed_version: vers, fixed_version: "0.90.3" );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

