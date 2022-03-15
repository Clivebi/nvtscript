CPE = "cpe:/a:elementor:website_builder";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.145199" );
	script_version( "2021-07-07T02:00:46+0000" );
	script_tag( name: "last_modification", value: "2021-07-07 02:00:46 +0000 (Wed, 07 Jul 2021)" );
	script_tag( name: "creation_date", value: "2021-01-20 04:29:08 +0000 (Wed, 20 Jan 2021)" );
	script_tag( name: "cvss_base", value: "4.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:S/C:N/I:P/A:N" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:H/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-08-25 12:48:00 +0000 (Tue, 25 Aug 2020)" );
	script_cve_id( "CVE-2020-20634" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_name( "WordPress Elementor Website Builder Plugin < 3.0.14 SVG Upload Vulnerability" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "gb_wordpress_plugin_http_detect.sc" );
	script_mandatory_keys( "wordpress/plugin/elementor/detected" );
	script_tag( name: "summary", value: "The Elementor Website Builder plugin for WordPress does not properly
  restrict SVG uploads." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "affected", value: "WordPress Elementor Website Builder plugin prior to version 3.0.14." );
	script_tag( name: "solution", value: "Update to version 3.0.14 or later." );
	script_xref( name: "URL", value: "https://wordpress.org/plugins/elementor/#developers" );
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
if(version_is_less( version: version, test_version: "3.0.14" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "3.0.14", install_path: location );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

