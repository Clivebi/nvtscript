CPE = "cpe:/a:contact_form_7_database_addon:contact_form_7_database_addon";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.145616" );
	script_version( "2021-08-17T09:01:01+0000" );
	script_tag( name: "last_modification", value: "2021-08-17 09:01:01 +0000 (Tue, 17 Aug 2021)" );
	script_tag( name: "creation_date", value: "2021-03-24 09:04:48 +0000 (Wed, 24 Mar 2021)" );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-03-22 19:58:00 +0000 (Mon, 22 Mar 2021)" );
	script_cve_id( "CVE-2021-24144" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_name( "WordPress Contact Form 7 Database Addon Plugin (CFDB7) < 1.2.5.8 CSV Injection Vulnerability" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "gb_wordpress_plugin_http_detect.sc" );
	script_mandatory_keys( "wordpress/plugin/photo-gallery/detected" );
	script_tag( name: "summary", value: "WordPress Contact Form 7 Database Addon plugin is prone to a CSV injection
  vulnerability." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "Unvalidated input leads to a vulnerability that lets remote attackers
  inject arbitrary formulas into CSV files." );
	script_tag( name: "affected", value: "WordPress Contact Form 7 Database Addon plugin before version 1.2.5.8." );
	script_tag( name: "solution", value: "Update to version 1.2.5.8 or later." );
	script_xref( name: "URL", value: "https://wpscan.com/vulnerability/143cdaff-c536-4ff9-8d64-c617511ddd48" );
	script_xref( name: "URL", value: "https://wordpress.org/plugins/contact-form-cfdb7/#developers" );
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
if(version_is_less( version: version, test_version: "1.2.5.8" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "1.2.5.8", install_path: location );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

