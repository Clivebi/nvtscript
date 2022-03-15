if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.112587" );
	script_version( "2021-08-30T09:01:25+0000" );
	script_tag( name: "last_modification", value: "2021-08-30 09:01:25 +0000 (Mon, 30 Aug 2021)" );
	script_tag( name: "creation_date", value: "2019-05-22 14:35:00 +0200 (Wed, 22 May 2019)" );
	script_tag( name: "cvss_base", value: "6.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:S/C:P/I:P/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-08-24 17:37:00 +0000 (Mon, 24 Aug 2020)" );
	script_cve_id( "CVE-2019-12239" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_name( "WordPress WP Booking System Plugin < 1.5.2 CSRF Vulnerability" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2019 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "gb_wordpress_plugin_http_detect.sc" );
	script_mandatory_keys( "wordpress/plugin/wp-booking-system/detected" );
	script_tag( name: "summary", value: "The WordPress plugin WP Booking System is prone to a CSRF vulnerability
  with the possible result of SQL injection." );
	script_tag( name: "impact", value: "Successful exploitation would allow an attacker to craft a malicious webpage that
  once visited by an authenticated administrative user, will trigger the SQL injection vulnerability." );
	script_tag( name: "affected", value: "WordPress WP Booking System plugin before version 1.5.2." );
	script_tag( name: "solution", value: "Update to version 1.5.2 or later." );
	script_xref( name: "URL", value: "https://wordpress.org/plugins/wp-booking-system/#developers" );
	script_xref( name: "URL", value: "http://dumpco.re/bugs/wp-plugin-wp-booking-system-sqli" );
	exit( 0 );
}
CPE = "cpe:/a:veribo:wp-booking-system";
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
if(version_is_less( version: version, test_version: "1.5.2" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "1.5.2", install_path: location );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

