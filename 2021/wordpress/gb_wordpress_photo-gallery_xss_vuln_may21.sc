CPE = "cpe:/a:10web:photo-gallery";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.146159" );
	script_version( "2021-08-17T09:01:01+0000" );
	script_tag( name: "last_modification", value: "2021-08-17 09:01:01 +0000 (Tue, 17 Aug 2021)" );
	script_tag( name: "creation_date", value: "2021-06-22 04:08:22 +0000 (Tue, 22 Jun 2021)" );
	script_tag( name: "cvss_base", value: "3.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:S/C:N/I:P/A:N" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:H/UI:R/S:C/C:L/I:L/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-06-09 00:46:00 +0000 (Wed, 09 Jun 2021)" );
	script_cve_id( "CVE-2021-24310" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_name( "WordPress Photo Gallery Plugin < 1.5.67 XSS Vulnerability" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "gb_wordpress_plugin_http_detect.sc" );
	script_mandatory_keys( "wordpress/plugin/photo-gallery/detected" );
	script_tag( name: "summary", value: "WordPress Photo Gallery plugin is prone to a cross-site
  scripting (XSS) vulnerability." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "The WordPress plugin does not properly sanitise the gallery
  title, allowing high privilege users to create one with XSS payload in it, which will be
  triggered when another user will view the gallery list or the affected gallery in the admin
  dashboard. This is due to an incomplete fix of CVE-2019-16117." );
	script_tag( name: "affected", value: "WordPress Photo Gallery plugin before version 1.5.67." );
	script_tag( name: "solution", value: "Update to version 1.5.67 or later." );
	script_xref( name: "URL", value: "https://wpscan.com/vulnerability/f34096ec-b1b0-471d-88a4-4699178a3165" );
	script_xref( name: "URL", value: "https://wordpress.org/plugins/photo-gallery/#developers" );
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
if(version_is_less( version: version, test_version: "1.5.67" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "1.5.67", install_path: location );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

