if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.112155" );
	script_version( "2020-11-10T11:45:08+0000" );
	script_tag( name: "last_modification", value: "2020-11-10 11:45:08 +0000 (Tue, 10 Nov 2020)" );
	script_tag( name: "creation_date", value: "2017-12-27 09:34:51 +0100 (Wed, 27 Dec 2017)" );
	script_tag( name: "cvss_base", value: "10.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:C/A:C" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_name( "WordPress Captcha Plugin Backdoor Vulnerability" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2017 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "gb_wordpress_plugin_http_detect.sc" );
	script_mandatory_keys( "wordpress/plugin/captcha/detected" );
	script_tag( name: "summary", value: "WordPress plugin Captcha is vulnerable to a backdoor vulnerability." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "affected", value: "WordPress Captcha plugin between version 4.3.6 and 4.4.4." );
	script_tag( name: "solution", value: "Update to version 4.4.5 or later.

  Another recommendation is that you uninstall the Captcha plugin immediately since the developer cannot be trusted." );
	script_xref( name: "URL", value: "https://www.wordfence.com/blog/2017/12/backdoor-captcha-plugin/" );
	exit( 0 );
}
CPE = "cpe:/a:simplywordpress:captcha";
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
if(version_in_range( version: version, test_version: "4.3.6", test_version2: "4.4.4" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "4.4.5", install_path: location );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

