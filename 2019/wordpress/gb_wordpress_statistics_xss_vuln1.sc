if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.140174" );
	script_version( "2021-08-30T10:01:19+0000" );
	script_tag( name: "last_modification", value: "2021-08-30 10:01:19 +0000 (Mon, 30 Aug 2021)" );
	script_tag( name: "creation_date", value: "2019-06-11 01:58:42 +0000 (Tue, 11 Jun 2019)" );
	script_tag( name: "cvss_base", value: "3.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:S/C:N/I:P/A:N" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:L/UI:R/S:C/C:L/I:L/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-06-03 12:50:00 +0000 (Mon, 03 Jun 2019)" );
	script_cve_id( "CVE-2019-12566" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_name( "WordPress WP Statistics Plugin <= 12.6.5 XSS Vulnerability" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2019 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "gb_wordpress_plugin_http_detect.sc" );
	script_mandatory_keys( "wordpress/plugin/wp-statistics/detected" );
	script_tag( name: "summary", value: "The WP Statistics plugin for WordPress has a stored XSS in
  includes/class-wp-statistics-pages.php. This is related to an account with the Editor role creating a post with
  a title that contains JavaScript, to attack an admin user." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "affected", value: "WP Statistics plugin 12.6.5 and prior." );
	script_tag( name: "solution", value: "Update to version 12.7 or later." );
	script_xref( name: "URL", value: "https://github.com/wp-statistics/wp-statistics/issues/271" );
	exit( 0 );
}
CPE = "cpe:/a:veronalabs:wp-statistics";
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
if(version_is_less_equal( version: version, test_version: "12.6.5" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "12.7", install_path: location );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

