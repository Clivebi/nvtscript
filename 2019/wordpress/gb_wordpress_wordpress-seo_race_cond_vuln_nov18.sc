if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.112515" );
	script_version( "2021-08-30T09:01:25+0000" );
	script_tag( name: "last_modification", value: "2021-08-30 09:01:25 +0000 (Mon, 30 Aug 2021)" );
	script_tag( name: "creation_date", value: "2019-02-18 09:59:00 +0100 (Mon, 18 Feb 2019)" );
	script_tag( name: "cvss_base", value: "6.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:S/C:P/I:P/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:H/PR:H/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-01-31 19:05:00 +0000 (Thu, 31 Jan 2019)" );
	script_cve_id( "CVE-2018-19370" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_name( "WordPress Yoast SEO Plugin before 9.2.0 Race Condition Vulnerability" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2019 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "gb_wordpress_plugin_http_detect.sc" );
	script_mandatory_keys( "wordpress/plugin/wordpress-seo/detected" );
	script_tag( name: "summary", value: "The WordPress plugin Yoast SEO is prone to a race condition vulnerability." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "affected", value: "WordPress Yoast SEO plugin before version 9.2.0." );
	script_tag( name: "solution", value: "Update to version 9.2.0 or later." );
	script_xref( name: "URL", value: "https://wordpress.org/plugins/wordpress-seo/#developers" );
	script_xref( name: "URL", value: "https://github.com/Yoast/wordpress-seo/pull/11502/commits/3bfa70a143f5ea3ee1934f3a1703bb5caf139ffa" );
	exit( 0 );
}
CPE = "cpe:/a:yoast:wordpress-seo";
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
if(version_is_less( version: version, test_version: "9.2.0" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "9.2.0", install_path: location );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

