if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.113696" );
	script_version( "2021-07-07T02:00:46+0000" );
	script_tag( name: "last_modification", value: "2021-07-07 02:00:46 +0000 (Wed, 07 Jul 2021)" );
	script_tag( name: "creation_date", value: "2020-05-29 09:39:15 +0000 (Fri, 29 May 2020)" );
	script_tag( name: "cvss_base", value: "3.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:S/C:N/I:P/A:N" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:L/UI:R/S:C/C:L/I:L/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-05-28 20:11:00 +0000 (Thu, 28 May 2020)" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_cve_id( "CVE-2020-13644" );
	script_name( "WordPress Accordion Plugin < 2.2.9 XSS Vulnerability" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "gb_wordpress_plugin_http_detect.sc" );
	script_mandatory_keys( "wordpress/plugin/accordions/detected" );
	script_tag( name: "summary", value: "The WordPress plugin Accordion is prone to
  a cross-site scripting (XSS) vulnerability." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "The unprotected AJAX wp_ajax_accordions_ajax_import_json action
  gives any authenticated user with Subscriber or higher permissions the ability to
  import a new accordion and inject malicious JavaScript into the site." );
	script_tag( name: "affected", value: "WordPress Accordion plugin through version 2.2.8." );
	script_tag( name: "solution", value: "Update to version 2.2.9 or later." );
	script_xref( name: "URL", value: "https://www.wordfence.com/blog/2020/04/vulnerability-patched-in-accordion-plugin/" );
	script_xref( name: "URL", value: "https://wordpress.org/plugins/accordions/#developers" );
	exit( 0 );
}
CPE = "cpe:/a:pickplugins:accordions";
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
if(version_is_less( version: version, test_version: "2.2.9" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "2.2.9", install_path: location );
	security_message( data: report, port: port );
	exit( 0 );
}
exit( 99 );

