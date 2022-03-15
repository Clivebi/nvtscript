if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.142690" );
	script_version( "2021-08-30T10:01:19+0000" );
	script_tag( name: "last_modification", value: "2021-08-30 10:01:19 +0000 (Mon, 30 Aug 2021)" );
	script_tag( name: "creation_date", value: "2019-08-01 07:53:38 +0000 (Thu, 01 Aug 2019)" );
	script_tag( name: "cvss_base", value: "5.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:P/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:H/A:L" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-08-24 17:37:00 +0000 (Mon, 24 Aug 2020)" );
	script_cve_id( "CVE-2019-6726" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_name( "WordPress Fastest Cache Plugin < 0.8.9.1 File Deletion Vulnerability" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2019 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "gb_wordpress_plugin_http_detect.sc" );
	script_mandatory_keys( "wordpress/plugin/wp-fastest-cache/detected" );
	script_tag( name: "summary", value: "The WordPress Fastest Cache plugin is prone to a file deletion vulnerability." );
	script_tag( name: "insight", value: "The WP Fastest Cache plugin for WordPress allows remote attackers to delete
  arbitrary files because wp_postratings_clear_fastest_cache and rm_folder_recursively in wpFastestCache.php
  mishandle ../ in an HTTP Referer header." );
	script_tag( name: "affected", value: "WordPress Fastest Cache plugin version 0.8.9.0 and prior." );
	script_tag( name: "solution", value: "Update to version 0.8.9.1 or later." );
	script_xref( name: "URL", value: "https://packetstormsecurity.com/files/152042" );
	script_xref( name: "URL", value: "https://wordpress.org/plugins/wp-fastest-cache/#developers" );
	exit( 0 );
}
CPE = "cpe:/a:emrevona:wp-fastest-cache";
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
if(version_is_less( version: version, test_version: "0.8.9.1" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "0.8.9.1", install_path: location );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

