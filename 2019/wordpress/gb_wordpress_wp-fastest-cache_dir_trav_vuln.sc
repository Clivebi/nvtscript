if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.142691" );
	script_version( "2021-08-30T10:01:19+0000" );
	script_tag( name: "last_modification", value: "2021-08-30 10:01:19 +0000 (Mon, 30 Aug 2021)" );
	script_tag( name: "creation_date", value: "2019-08-01 08:01:51 +0000 (Thu, 01 Aug 2019)" );
	script_tag( name: "cvss_base", value: "6.4" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:N" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-08-13 10:15:00 +0000 (Tue, 13 Aug 2019)" );
	script_cve_id( "CVE-2019-13635" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_name( "WordPress Fastest Cache Plugin < 0.8.9.6 Directory Traversal Vulnerability" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2019 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "gb_wordpress_plugin_http_detect.sc" );
	script_mandatory_keys( "wordpress/plugin/wp-fastest-cache/detected" );
	script_tag( name: "summary", value: "The WordPress Fastest Cache plugin is prone to a directory traversal
  vulnerability." );
	script_tag( name: "affected", value: "WordPress Fastest Cache plugin version 0.8.9.5 and prior." );
	script_tag( name: "solution", value: "Update to version 0.8.9.6 or later." );
	script_xref( name: "URL", value: "https://packetstormsecurity.com/files/153821/WordPress-WP-Fastest-Cache-0.8.9.5-Directory-Traversal.html" );
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
if(version_is_less( version: version, test_version: "0.8.9.6" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "0.8.9.6", install_path: location );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

