if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.112512" );
	script_version( "2020-11-10T11:45:08+0000" );
	script_tag( name: "last_modification", value: "2020-11-10 11:45:08 +0000 (Tue, 10 Nov 2020)" );
	script_tag( name: "creation_date", value: "2019-02-14 11:11:11 +0100 (Thu, 14 Feb 2019)" );
	script_tag( name: "cvss_base", value: "8.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:S/C:C/I:C/A:C" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_name( "WordPress Simple Social Buttons Plugin 2.0.4 < 2.0.22 Privilege Escalation Vulnerability" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2019 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "gb_wordpress_plugin_http_detect.sc" );
	script_mandatory_keys( "wordpress/plugin/simple-social-buttons/detected" );
	script_tag( name: "summary", value: "The WordPress plugin Simple Social Buttons is prone to a privilege escalation vulnerability." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "affected", value: "WordPress Simple Social Buttons plugin version 2.0.4 before 2.0.22" );
	script_tag( name: "solution", value: "Update to version 2.0.22 or later." );
	script_xref( name: "URL", value: "https://www.webarxsecurity.com/wordpress-plugin-simple-social-buttons/" );
	script_xref( name: "URL", value: "https://wordpress.org/plugins/simple-social-buttons/#developers" );
	exit( 0 );
}
CPE = "cpe:/a:wpbrigade:simple-social-buttons";
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
if(version_in_range( version: version, test_version: "2.0.4", test_version2: "2.0.21" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "2.0.22", install_path: location );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

