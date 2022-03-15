CPE = "cpe:/a:10web:photo-gallery";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.146543" );
	script_version( "2021-08-24T03:01:09+0000" );
	script_tag( name: "last_modification", value: "2021-08-24 03:01:09 +0000 (Tue, 24 Aug 2021)" );
	script_tag( name: "creation_date", value: "2021-08-23 08:06:24 +0000 (Mon, 23 Aug 2021)" );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:P/A:N" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-08-23 16:43:00 +0000 (Mon, 23 Aug 2021)" );
	script_cve_id( "CVE-2021-24362", "CVE-2021-24363" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_name( "WordPress Photo Gallery Plugin < 1.5.75 Multiple Vulnerabilities" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "gb_wordpress_plugin_http_detect.sc" );
	script_mandatory_keys( "wordpress/plugin/photo-gallery/detected" );
	script_tag( name: "summary", value: "WordPress Photo Gallery plugin is prone to multiple vulnerabilities." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "The following vulnerabilities exist:

  - CVE-2021-24362: The plugin does not ensure that uploaded SVG files added to a gallery do not
  contain malicious content. As a result, users allowed to add images to gallery can upload an SVG
  file containing JavaScript code, which will be executed when accessing the image directly (ie in
  the /wp-content/uploads/photo-gallery/ folder), leading to a Cross-Site Scripting (XSS) issue.

  - CVE-2021-24363: The plugin does not ensure that uploaded files are kept inside its uploads
  folder, allowing high privilege users to put images/SVG anywhere in the filesystem via a path
  traversal vector." );
	script_tag( name: "affected", value: "WordPress Photo Gallery plugin before version 1.5.75." );
	script_tag( name: "solution", value: "Update to version 1.5.75 or later." );
	script_xref( name: "URL", value: "https://wpscan.com/vulnerability/57823dcb-2149-47f7-aae2-d9f04dce851a" );
	script_xref( name: "URL", value: "https://wpscan.com/vulnerability/1628935f-1d7d-4609-b7a9-e5526499c974" );
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
if(version_is_less( version: version, test_version: "1.5.75" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "1.5.75", install_path: location );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

