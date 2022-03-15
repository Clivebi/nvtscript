if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.112236" );
	script_version( "2021-05-27T06:00:15+0200" );
	script_tag( name: "last_modification", value: "2021-05-27 06:00:15 +0200 (Thu, 27 May 2021)" );
	script_tag( name: "creation_date", value: "2018-02-20 11:30:00 +0100 (Tue, 20 Feb 2018)" );
	script_tag( name: "cvss_base", value: "3.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:S/C:N/I:P/A:N" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:L/UI:R/S:C/C:L/I:L/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-07-08 16:23:00 +0000 (Mon, 08 Jul 2019)" );
	script_cve_id( "CVE-2015-2324" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_name( "WordPress Photo Gallery Plugin XSS Vulnerability" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "gb_wordpress_plugin_http_detect.sc" );
	script_mandatory_keys( "wordpress/plugin/photo-gallery/detected" );
	script_tag( name: "summary", value: "Cross-site scripting (XSS) vulnerability in the filemanager in the Photo Gallery plugin for WordPress
allows remote authenticated users with edit permission to inject arbitrary web script or HTML via unspecified vectors." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "affected", value: "WordPress Web-Dorado 'Photo Gallery by WD - Responsive Photo Gallery' plugin before 1.2.13." );
	script_tag( name: "solution", value: "Update to version 1.2.13 or later." );
	script_xref( name: "URL", value: "https://fortiguard.com/zeroday/FG-VD-15-009" );
	script_xref( name: "URL", value: "https://wordpress.org/plugins/photo-gallery/#developers" );
	exit( 0 );
}
CPE = "cpe:/a:10web:photo-gallery";
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
if(version_is_less( version: version, test_version: "1.2.13" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "1.2.13", install_path: location );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

