if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.112127" );
	script_version( "2021-09-09T10:07:02+0000" );
	script_tag( name: "last_modification", value: "2021-09-09 10:07:02 +0000 (Thu, 09 Sep 2021)" );
	script_tag( name: "creation_date", value: "2017-11-17 12:00:00 +0100 (Fri, 17 Nov 2017)" );
	script_tag( name: "cvss_base", value: "3.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:S/C:N/I:P/A:N" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:H/UI:R/S:C/C:L/I:L/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2017-12-03 17:34:00 +0000 (Sun, 03 Dec 2017)" );
	script_cve_id( "CVE-2017-16842" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_name( "WordPress Yoast SEO Plugin XSS Vulnerability" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2017 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "gb_wordpress_plugin_http_detect.sc" );
	script_mandatory_keys( "wordpress/plugin/wordpress-seo/detected" );
	script_tag( name: "summary", value: "A cross-site scripting (XSS) vulnerability in admin/google_search_console/class-gsc-table.php
in the Yoast SEO plugin for WordPress allows remote attackers to inject arbitrary web script or HTML." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "affected", value: "WordPress Yoast SEO plugin before version 5.8.0." );
	script_tag( name: "solution", value: "Update to version 5.8.0 or later." );
	script_xref( name: "URL", value: "https://wordpress.org/plugins/wordpress-seo/#developers" );
	script_xref( name: "URL", value: "https://plugins.trac.wordpress.org/changeset/1766831/wordpress-seo/trunk/admin/google_search_console/class-gsc-table.php" );
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
if(version_is_less( version: version, test_version: "5.8.0" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "5.8.0", install_path: location );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

