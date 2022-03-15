CPE = "cpe:/a:php-fusion:php-fusion";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.15392" );
	script_version( "2020-05-11T07:30:32+0000" );
	script_tag( name: "last_modification", value: "2020-05-11 07:30:32 +0000 (Mon, 11 May 2020)" );
	script_tag( name: "creation_date", value: "2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)" );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:N/A:N" );
	script_name( "PHP-Fusion homepage address XSS" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2004 David Maciejak" );
	script_family( "Web application abuses" );
	script_dependencies( "secpod_php_fusion_detect.sc" );
	script_mandatory_keys( "php-fusion/detected" );
	script_tag( name: "solution", value: "Apply the patch for 4.01." );
	script_tag( name: "summary", value: "A vulnerability exists in the remote version of PHP-Fusion that may
  allow an attacker to execute arbitrary HTML and script code in the context of the user's browser." );
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
version = infos["version"];
location = infos["location"];
if(version_is_less_equal( version: version, test_version: "4.00" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "4.01", install_path: location );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

