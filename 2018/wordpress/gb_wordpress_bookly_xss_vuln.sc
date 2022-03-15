if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.112220" );
	script_version( "2021-05-27T06:00:15+0200" );
	script_tag( name: "last_modification", value: "2021-05-27 06:00:15 +0200 (Thu, 27 May 2021)" );
	script_tag( name: "creation_date", value: "2018-02-13 08:46:00 +0100 (Tue, 13 Feb 2018)" );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:P/A:N" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2018-02-27 19:38:00 +0000 (Tue, 27 Feb 2018)" );
	script_cve_id( "CVE-2018-6891" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_name( "WordPress Bookly Plugin XSS Vulnerability" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "gb_wordpress_plugin_http_detect.sc" );
	script_mandatory_keys( "wordpress/plugin/bookly-responsive-appointment-booking-tool/detected" );
	script_tag( name: "summary", value: "Bookly plugin for WordPress is prone to a cross-site scripting (XSS) vulnerability." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "affected", value: "WordPress Bookly plugin before version 14.5." );
	script_tag( name: "solution", value: "Update to version 14.5 or later." );
	script_xref( name: "URL", value: "https://wordpress.org/plugins/bookly-responsive-appointment-booking-tool/#developers" );
	script_xref( name: "URL", value: "https://www.gubello.me/blog/bookly-blind-stored-xss/" );
	exit( 0 );
}
CPE = "cpe:/a:bookly:bookly-responsive-appointment-booking-tool";
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
if(version_is_less( version: version, test_version: "14.5" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "14.5", install_path: location );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

