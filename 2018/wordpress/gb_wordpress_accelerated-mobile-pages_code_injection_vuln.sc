if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.112432" );
	script_version( "2020-08-06T13:39:56+0000" );
	script_tag( name: "last_modification", value: "2020-08-06 13:39:56 +0000 (Thu, 06 Aug 2020)" );
	script_tag( name: "creation_date", value: "2018-11-13 12:21:00 +0100 (Tue, 13 Nov 2018)" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_name( "WordPress AMP for WP - Accelerated Mobile Pages Plugin < 0.9.97.20 Unauthorized Code Injection Vulnerability" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "gb_wordpress_plugin_http_detect.sc" );
	script_mandatory_keys( "wordpress/plugin/accelerated-mobile-pages/detected" );
	script_tag( name: "summary", value: "WordPress Accelerated Mobile Pages plugin is prone to a code injection vulnerability." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "affected", value: "WordPress Accelerated Mobile Pages plugin before version 0.9.97.20." );
	script_tag( name: "solution", value: "Update the plugin to version 0.9.97.20 or later." );
	script_xref( name: "URL", value: "https://www.webarxsecurity.com/amp-plugin-vulnerability/" );
	script_xref( name: "URL", value: "https://wordpress.org/plugins/accelerated-mobile-pages/#developers" );
	exit( 0 );
}
CPE = "cpe:/a:ahmed_kaludi:accelerated-mobile-pages";
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
if(version_is_less( version: version, test_version: "0.9.97.20" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "0.9.97.20", install_path: location );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

