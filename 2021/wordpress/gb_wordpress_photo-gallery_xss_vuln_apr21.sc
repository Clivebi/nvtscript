CPE = "cpe:/a:10web:photo-gallery";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.146158" );
	script_version( "2021-08-17T09:01:01+0000" );
	script_tag( name: "last_modification", value: "2021-08-17 09:01:01 +0000 (Tue, 17 Aug 2021)" );
	script_tag( name: "creation_date", value: "2021-06-22 04:02:28 +0000 (Tue, 22 Jun 2021)" );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:P/A:N" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-05-21 20:44:00 +0000 (Fri, 21 May 2021)" );
	script_cve_id( "CVE-2021-24291" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_name( "WordPress Photo Gallery Plugin < 1.5.69 XSS Vulnerability" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "gb_wordpress_plugin_http_detect.sc" );
	script_mandatory_keys( "wordpress/plugin/photo-gallery/detected" );
	script_tag( name: "summary", value: "WordPress Photo Gallery plugin is prone to a cross-site
  scripting (XSS) vulnerability." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "The WordPress plugin is vulnerable to a reflected XSS issues
  via the gallery_id, tag, album_id and _id GET parameters passed to the bwg_frontend_data AJAX
  action (available to both unauthenticated and authenticated users)." );
	script_tag( name: "affected", value: "WordPress Photo Gallery plugin before version 1.5.69." );
	script_tag( name: "solution", value: "Update to version 1.5.69 or later." );
	script_xref( name: "URL", value: "https://wpscan.com/vulnerability/cfb982b2-8b6d-4345-b3ab-3d2b130b873a" );
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
if(version_is_less( version: version, test_version: "1.5.69" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "1.5.69", install_path: location );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

