if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.112517" );
	script_version( "2021-08-30T09:01:25+0000" );
	script_tag( name: "last_modification", value: "2021-08-30 09:01:25 +0000 (Mon, 30 Aug 2021)" );
	script_tag( name: "creation_date", value: "2019-02-18 10:13:00 +0100 (Mon, 18 Feb 2019)" );
	script_tag( name: "cvss_base", value: "6.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:S/C:P/I:P/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-01-07 15:04:00 +0000 (Mon, 07 Jan 2019)" );
	script_cve_id( "CVE-2018-20154", "CVE-2018-20155", "CVE-2018-20156" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_name( "WordPress WP Maintenance Mode Plugin before 2.0.7 Multiple Vulnerabilities" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2019 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "gb_wordpress_plugin_http_detect.sc" );
	script_mandatory_keys( "wordpress/plugin/wp-maintenance-mode/detected" );
	script_tag( name: "summary", value: "The WordPress plugin WP Maintenance Mode is prone to multiple vulnerabilities." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "affected", value: "WordPress WP Maintenance Mode plugin before version 2.0.7." );
	script_tag( name: "solution", value: "Update to version 2.0.7 or later." );
	script_xref( name: "URL", value: "https://wordpress.org/plugins/wp-maintenance-mode/#developers" );
	script_xref( name: "URL", value: "https://www.wordfence.com/blog/2016/07/3-vulnerabilities-wp-maintenance-mode/" );
	exit( 0 );
}
CPE = "cpe:/a:designmodo:wp-maintenance-mode";
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
if(version_is_less( version: version, test_version: "2.0.7" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "2.0.7", install_path: location );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

