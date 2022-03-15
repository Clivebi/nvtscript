CPE = "cpe:/a:vbulletin:vbulletin";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.16203" );
	script_version( "2020-05-05T09:44:01+0000" );
	script_tag( name: "last_modification", value: "2020-05-05 09:44:01 +0000 (Tue, 05 May 2020)" );
	script_tag( name: "creation_date", value: "2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)" );
	script_bugtraq_id( 12299 );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_name( "vBulletin Init.PHP unspecified vulnerability" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2005 David Maciejak" );
	script_family( "Web application abuses" );
	script_dependencies( "vbulletin_detect.sc" );
	script_mandatory_keys( "vbulletin/detected" );
	script_tag( name: "solution", value: "Upgrade to vBulletin 3.0.5 or newer." );
	script_tag( name: "summary", value: "It is reported that versions 3.0.0 through to 3.0.4 of
  vBulletin are prone to a security flaw in 'includes/init.php'. Successful exploitation
  requires that 'register_globals' is enabled." );
	script_xref( name: "URL", value: "http://secunia.com/advisories/13901/" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "remote_banner" );
	exit( 0 );
}
require("version_func.inc.sc");
require("host_details.inc.sc");
if(!port = get_app_port( cpe: CPE )){
	exit( 0 );
}
if(!infos = get_app_version_and_location( cpe: CPE, port: port, exit_no_version: TRUE )){
	exit( 0 );
}
vers = infos["version"];
path = infos["location"];
if(version_in_range( version: vers, test_version: "3.0.0", test_version2: "3.0.4" )){
	report = report_fixed_ver( installed_version: vers, fixed_version: "3.0.5", install_path: path );
	security_message( data: report, port: port );
	exit( 0 );
}
exit( 99 );

