CPE = "cpe:/a:seopress:seopress";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.146544" );
	script_version( "2021-08-25T06:00:59+0000" );
	script_tag( name: "last_modification", value: "2021-08-25 06:00:59 +0000 (Wed, 25 Aug 2021)" );
	script_tag( name: "creation_date", value: "2021-08-23 08:25:40 +0000 (Mon, 23 Aug 2021)" );
	script_tag( name: "cvss_base", value: "3.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:S/C:N/I:P/A:N" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:L/UI:R/S:C/C:L/I:L/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-08-23 20:16:00 +0000 (Mon, 23 Aug 2021)" );
	script_cve_id( "CVE-2021-34641" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_name( "WordPress SEOPress Plugin 5.0.x < 5.0.4 XSS Vulnerability" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "gb_wordpress_plugin_http_detect.sc" );
	script_mandatory_keys( "wordpress/plugin/wp-seopress/detected" );
	script_tag( name: "summary", value: "WordPress SEOPress plugin is prone to a cross-site scripting
  (XSS) vulnerability." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "The SEOPress WordPress plugin is vulnerable to a stored XSS
  via the processPut function found in the ~/src/Actions/Api/TitleDescriptionMeta.php file which
  allows authenticated attackers to inject arbitrary web scripts." );
	script_tag( name: "affected", value: "WordPress SEOPress plugin version 5.0.x through 5.0.3." );
	script_tag( name: "solution", value: "Update to version 5.0.4 or later." );
	script_xref( name: "URL", value: "https://www.wordfence.com/blog/2021/08/xss-vulnerability-patched-in-seopress-affects-100000-sites/" );
	script_xref( name: "URL", value: "https://wordpress.org/plugins/wp-seopress/#developers" );
	exit( 0 );
}
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
if(version_in_range( version: version, test_version: "5.0.0", test_version2: "5.0.3" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "5.0.4", install_path: location );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

