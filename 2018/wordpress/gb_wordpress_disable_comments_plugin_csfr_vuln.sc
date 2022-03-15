if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.107302" );
	script_version( "2021-05-27T06:00:15+0200" );
	script_tag( name: "last_modification", value: "2021-05-27 06:00:15 +0200 (Thu, 27 May 2021)" );
	script_tag( name: "creation_date", value: "2018-03-20 14:15:46 +0100 (Tue, 20 Mar 2018)" );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2018-04-17 14:57:00 +0000 (Tue, 17 Apr 2018)" );
	script_cve_id( "CVE-2014-2550" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_name( "WordPress Disable Comments Plugin CSRF Vulnerability" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "gb_wordpress_plugin_http_detect.sc" );
	script_mandatory_keys( "wordpress/plugin/disable-comments/detected" );
	script_tag( name: "summary", value: "The installed Disable Comments plugin for WordPress has a Cross-site
  request forgery (CSRF) vulnerability." );
	script_tag( name: "impact", value: "This flaw allows remote attackers to hijack the authentication of administrators
  for requests that enable comments via a request to the disable_comments_settings page to wp-admin/options-general.php." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "affected", value: "WordPress Disable Comments plugin before 1.0.4." );
	script_tag( name: "solution", value: "Update to version 1.0.4 or later." );
	script_xref( name: "URL", value: "https://wordpress.org/plugins/disable-comments/#developers" );
	exit( 0 );
}
CPE = "cpe:/a:rayofsolaris:disable-comments";
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
if(version_is_less( version: version, test_version: "1.0.4" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "1.0.4", install_path: location );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

