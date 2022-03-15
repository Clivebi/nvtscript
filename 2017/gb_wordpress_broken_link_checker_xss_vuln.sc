if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.112033" );
	script_version( "2021-09-10T09:01:40+0000" );
	script_tag( name: "last_modification", value: "2021-09-10 09:01:40 +0000 (Fri, 10 Sep 2021)" );
	script_tag( name: "creation_date", value: "2017-09-01 12:08:31 +0200 (Fri, 01 Sep 2017)" );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:P/A:N" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-03-14 00:15:00 +0000 (Sat, 14 Mar 2020)" );
	script_cve_id( "CVE-2015-5057" );
	script_bugtraq_id( 75421 );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_name( "WordPress Broken Link Checker XSS Vulnerability" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2017 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "gb_wordpress_plugin_http_detect.sc" );
	script_mandatory_keys( "wordpress/plugin/broken-link-checker/detected" );
	script_tag( name: "summary", value: "There exists a cross-site scripting (XSS) vulnerability in the WordPress admin panel when the Broken Link Checker plugin is installed." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "affected", value: "WordPress Broken Link Checker plugin before 1.10.9." );
	script_tag( name: "solution", value: "Update to version 1.10.9 or later." );
	script_xref( name: "URL", value: "https://wordpress.org/plugins/broken-link-checker/#developers" );
	exit( 0 );
}
CPE = "cpe:/a:managewp:broken-link-checker";
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
if(version_is_less( version: version, test_version: "1.10.9" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "1.10.9", install_path: location );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

