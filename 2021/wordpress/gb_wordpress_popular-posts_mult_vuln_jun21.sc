CPE = "cpe:/a:cabrerahector:popular_posts";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.146207" );
	script_version( "2021-08-17T12:00:57+0000" );
	script_tag( name: "last_modification", value: "2021-08-17 12:00:57 +0000 (Tue, 17 Aug 2021)" );
	script_tag( name: "creation_date", value: "2021-07-02 03:45:07 +0000 (Fri, 02 Jul 2021)" );
	script_tag( name: "cvss_base", value: "3.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:S/C:N/I:P/A:N" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:L/UI:R/S:C/C:L/I:L/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-07-01 19:01:00 +0000 (Thu, 01 Jul 2021)" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_cve_id( "CVE-2021-20746" );
	script_name( "WordPress Popular Posts Plugin < 5.3.3 Multiple Vulnerabilities" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "gb_wordpress_plugin_http_detect.sc" );
	script_mandatory_keys( "wordpress/plugin/wordpress-popular-posts/detected" );
	script_tag( name: "summary", value: "The WordPress Popular Posts plugin is prone to multiple
  vulnerabilities." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "The following vulnerabilities exist:

  - CVE-2021-20746: XSS allows a remote authenticated attacker to inject an arbitrary script via
  unspecified vectors.

  - Code injection" );
	script_tag( name: "affected", value: "WordPress Popular Posts plugin version 5.3.2 and prior." );
	script_tag( name: "solution", value: "Update to version 5.3.3 or later." );
	script_xref( name: "URL", value: "https://wordpress.org/plugins/wordpress-popular-posts/#developers" );
	script_xref( name: "URL", value: "https://cabrerahector.com/wordpress/wordpress-popular-posts-5-3-improved-php-8-support-retina-display-support-and-more/#minor-updates-and-hotfixes" );
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
if(version_is_less( version: version, test_version: "5.3.3" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "5.3.3", install_path: location );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

