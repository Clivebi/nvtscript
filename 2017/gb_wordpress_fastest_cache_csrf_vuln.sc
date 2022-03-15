if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.112053" );
	script_version( "2021-09-13T13:01:42+0000" );
	script_tag( name: "last_modification", value: "2021-09-13 13:01:42 +0000 (Mon, 13 Sep 2021)" );
	script_tag( name: "creation_date", value: "2017-09-25 09:35:51 +0200 (Mon, 25 Sep 2017)" );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-09-01 06:15:00 +0000 (Sun, 01 Sep 2019)" );
	script_cve_id( "CVE-2015-4089" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_name( "WordPress Fastest Cache Plugin CSRF Vulnerability" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2017 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "gb_wordpress_plugin_http_detect.sc" );
	script_mandatory_keys( "wordpress/plugin/wp-fastest-cache/detected" );
	script_tag( name: "summary", value: "Multiple cross-site request forgery (CSRF) vulnerabilities in the optionsPageRequest function in admin.php in WP Fastest Cache plugin before 0.8.3.5 for WordPress allow remote attackers to hijack the authentication of unspecified victims for requests that call the (1) saveOption, (2) deleteCache, (3) deleteCssAndJsCache, or (4) addCacheTimeout method via the wpFastestCachePage parameter in the WpFastestCacheOptions/ page." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "affected", value: "WordPress Fastest Cache plugin version 0.8.3.4 and prior." );
	script_tag( name: "solution", value: "Update to version 0.8.3.5 or later." );
	script_xref( name: "URL", value: "https://wordpress.org/plugins/wp-fastest-cache/#developers" );
	script_xref( name: "URL", value: "http://www.openwall.com/lists/oss-security/2015/05/26/20" );
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
if(version_is_less( version: version, test_version: "0.8.3.5" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "0.8.3.5", install_path: location );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

