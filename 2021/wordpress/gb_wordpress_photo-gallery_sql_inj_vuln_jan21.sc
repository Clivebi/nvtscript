CPE = "cpe:/a:10web:photo-gallery";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.145615" );
	script_version( "2021-08-17T09:01:01+0000" );
	script_tag( name: "last_modification", value: "2021-08-17 09:01:01 +0000 (Tue, 17 Aug 2021)" );
	script_tag( name: "creation_date", value: "2021-03-24 08:35:23 +0000 (Wed, 24 Mar 2021)" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-03-22 19:58:00 +0000 (Mon, 22 Mar 2021)" );
	script_cve_id( "CVE-2021-24139" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_name( "WordPress Photo Gallery Plugin < 1.5.55 SQLi Vulnerability" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "gb_wordpress_plugin_http_detect.sc" );
	script_mandatory_keys( "wordpress/plugin/photo-gallery/detected" );
	script_tag( name: "summary", value: "WordPress Photo Gallery plugin is prone to an SQL injection (SQLi) vulnerability." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "Unvalidated input leads to SQL injection via the frontend/models/model.php
  bwg_search_x parameter." );
	script_tag( name: "affected", value: "WordPress Photo Gallery plugin before version 1.5.55." );
	script_tag( name: "solution", value: "Update to version 1.5.55 or later." );
	script_xref( name: "URL", value: "https://wpscan.com/vulnerability/2e33088e-7b93-44af-aa6a-e5d924f86e28" );
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
if(version_is_less( version: version, test_version: "1.5.55" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "1.5.55", install_path: location );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

