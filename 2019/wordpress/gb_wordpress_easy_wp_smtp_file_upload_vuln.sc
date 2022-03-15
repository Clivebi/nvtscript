if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.142166" );
	script_version( "2020-08-06T13:39:56+0000" );
	script_tag( name: "last_modification", value: "2020-08-06 13:39:56 +0000 (Thu, 06 Aug 2020)" );
	script_tag( name: "creation_date", value: "2019-03-26 09:35:55 +0000 (Tue, 26 Mar 2019)" );
	script_tag( name: "cvss_base", value: "10.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:C/A:C" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_name( "WordPress Easy WP SMTP Plugin 1.3.9 RCE Vulnerability" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2019 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "gb_wordpress_plugin_http_detect.sc" );
	script_mandatory_keys( "wordpress/plugin/easy-wp-smtp/detected" );
	script_tag( name: "summary", value: "WordPress Easy WP SMTP Plugin is prone to a remote code execution
vulnerability." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "affected", value: "WordPress Easy WP SMTP plugin version 1.3.9." );
	script_tag( name: "solution", value: "Update to version 1.3.9.1 or later." );
	script_xref( name: "URL", value: "https://blog.nintechnet.com/critical-0day-vulnerability-fixed-in-wordpress-easy-wp-smtp-plugin/" );
	exit( 0 );
}
CPE = "cpe:/a:wp-ecommerce:easy-wp-smtp";
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
if(version_is_equal( version: version, test_version: "1.3.9" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "1.3.9.1", install_path: location );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

