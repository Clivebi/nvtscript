if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.112441" );
	script_version( "2020-08-06T13:39:56+0000" );
	script_tag( name: "last_modification", value: "2020-08-06 13:39:56 +0000 (Thu, 06 Aug 2020)" );
	script_tag( name: "creation_date", value: "2018-11-26 13:28:00 +0100 (Mon, 26 Nov 2018)" );
	script_tag( name: "cvss_base", value: "7.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:N/A:N" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_tag( name: "solution_type", value: "WillNotFix" );
	script_name( "WordPress Pods Plugin <= 2.7.9 Database Disclosure Vulnerability" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "gb_wordpress_plugin_http_detect.sc" );
	script_mandatory_keys( "wordpress/plugin/pods/detected" );
	script_tag( name: "summary", value: "WordPress Pods plugin is prone to a database disclosure vulnerability." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "affected", value: "WordPress Pods plugin through version 2.7.9." );
	script_tag( name: "solution", value: "No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one." );
	script_xref( name: "URL", value: "https://cxsecurity.com/issue/WLB-2018110194" );
	script_xref( name: "URL", value: "https://wordpress.org/plugins/pods/#developers" );
	exit( 0 );
}
CPE = "cpe:/a:pods:pods";
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
if(version_is_less_equal( version: version, test_version: "2.7.9" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "None", install_path: location );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

