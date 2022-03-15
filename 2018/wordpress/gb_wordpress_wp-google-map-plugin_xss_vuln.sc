if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.112285" );
	script_version( "2021-05-27T06:00:15+0200" );
	script_tag( name: "last_modification", value: "2021-05-27 06:00:15 +0200 (Thu, 27 May 2021)" );
	script_tag( name: "creation_date", value: "2018-05-16 13:24:00 +0200 (Wed, 16 May 2018)" );
	script_tag( name: "cvss_base", value: "3.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:S/C:N/I:P/A:N" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:L/UI:R/S:C/C:L/I:L/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-11-20 22:15:00 +0000 (Wed, 20 Nov 2019)" );
	script_cve_id( "CVE-2018-0577" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_name( "WordPress WP Google Map Plugin < 4.0.4 XSS Vulnerability" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "gb_wordpress_plugin_http_detect.sc" );
	script_mandatory_keys( "wordpress/plugin/wp-google-map-plugin/detected" );
	script_tag( name: "summary", value: "WP Google Map Plugin for WordPress is prone to a cross-site scripting vulnerability." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "affected", value: "WordPress WP Google Map Plugin before version 4.0.4." );
	script_tag( name: "solution", value: "Update to version 4.0.4 or later." );
	script_xref( name: "URL", value: "http://jvn.jp/en/jp/JVN01040170/index.html" );
	script_xref( name: "URL", value: "https://wordpress.org/plugins/wp-google-map-plugin/#developers" );
	exit( 0 );
}
CPE = "cpe:/a:flippercode:wp-google-map-plugin";
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
if(version_is_less( version: version, test_version: "4.0.4" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "4.0.4", install_path: location );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

