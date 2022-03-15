if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.112181" );
	script_version( "2021-05-27T06:00:15+0200" );
	script_tag( name: "last_modification", value: "2021-05-27 06:00:15 +0200 (Thu, 27 May 2021)" );
	script_tag( name: "creation_date", value: "2018-01-09 09:40:00 +0100 (Tue, 09 Jan 2018)" );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2018-01-29 12:32:00 +0000 (Mon, 29 Jan 2018)" );
	script_cve_id( "CVE-2018-5284", "CVE-2018-5285" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_name( "WordPress ImageInject Plugin Multiple Vulnerabilities" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "gb_wordpress_plugin_http_detect.sc" );
	script_mandatory_keys( "wordpress/plugin/wp-inject/detected" );
	script_tag( name: "summary", value: "The ImageInject plugin for WordPress is prone to cross-site scripting (XSS)
  and cross-site request forgery (CSRF) vulnerabilities." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "affected", value: "WordPress ImageInject plugin up to and including version 1.15." );
	script_tag( name: "solution", value: "Update to version 1.16 or later." );
	script_xref( name: "URL", value: "https://github.com/d4wner/Vulnerabilities-Report/blob/master/ImageInject.md" );
	script_xref( name: "URL", value: "https://plugins.trac.wordpress.org/changeset/1812423/wp-inject" );
	exit( 0 );
}
CPE = "cpe:/a:wpscoop:wp-inject";
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
if(version_is_less_equal( version: version, test_version: "1.15" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "1.16", install_path: location );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

