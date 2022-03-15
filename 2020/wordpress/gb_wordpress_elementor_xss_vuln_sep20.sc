if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.113751" );
	script_version( "2021-07-07T02:00:46+0000" );
	script_tag( name: "last_modification", value: "2021-07-07 02:00:46 +0000 (Wed, 07 Jul 2021)" );
	script_tag( name: "creation_date", value: "2020-09-03 09:37:34 +0000 (Thu, 03 Sep 2020)" );
	script_tag( name: "cvss_base", value: "3.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:S/C:N/I:P/A:N" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:L/UI:R/S:C/C:L/I:L/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-09-04 16:47:00 +0000 (Fri, 04 Sep 2020)" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_cve_id( "CVE-2020-15020" );
	script_name( "WordPress Elementor Page Builder Plugin <= 2.9.13 XSS Vulnerability" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "gb_wordpress_plugin_http_detect.sc" );
	script_mandatory_keys( "wordpress/plugin/elementor/detected" );
	script_tag( name: "summary", value: "The WordPress plugin Elementor Page Builder
  is prone to a cross-site scripting (XSS) vulnerability." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "The vulnerability is exploitable via the Name Your Template field." );
	script_tag( name: "impact", value: "Successful exploitation would allow an attacker
  to inject arbitrary HTML and JavaScript into the page." );
	script_tag( name: "affected", value: "WordPress Elementor Page Builder plugin through version 2.9.13." );
	script_tag( name: "solution", value: "Update to version 2.9.14 or later." );
	script_xref( name: "URL", value: "http://hidden-one.co.in/2020/07/07/cve-2020-1020-stored-xss-on-elementor-wordpress-plugin/" );
	exit( 0 );
}
CPE = "cpe:/a:elementor:elementor_page_builder";
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
if(version_is_less( version: version, test_version: "2.9.14" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "2.9.14", install_path: location );
	security_message( data: report, port: port );
	exit( 0 );
}
exit( 99 );

