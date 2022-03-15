if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.112570" );
	script_version( "2021-08-30T10:01:19+0000" );
	script_tag( name: "last_modification", value: "2021-08-30 10:01:19 +0000 (Mon, 30 Aug 2021)" );
	script_tag( name: "creation_date", value: "2019-04-29 13:53:00 +0200 (Mon, 29 Apr 2019)" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-05-01 15:47:00 +0000 (Wed, 01 May 2019)" );
	script_cve_id( "CVE-2019-11565" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_name( "WordPress Print My Blog Plugin < 1.6.7 SSRF Vulnerability" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2019 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "gb_wordpress_plugin_http_detect.sc" );
	script_mandatory_keys( "wordpress/plugin/print-my-blog/detected" );
	script_tag( name: "summary", value: "The WordPress plugin Print My Blog is prone to an SSRF vulnerability." );
	script_tag( name: "insight", value: "The wp_remote_get()[2] function is called with an attacker
  controllable URL, resulting in unauthenticated SSRF. By setting up a malicious web server,
  the SSRF can be further chained to launch a reflected XSS attack." );
	script_tag( name: "affected", value: "WordPress Print My Blog plugin before version 1.6.7." );
	script_tag( name: "solution", value: "Update to version 1.6.7 or later." );
	script_xref( name: "URL", value: "http://dumpco.re/bugs/wp-plugin-print-my-blog-ssrf" );
	script_xref( name: "URL", value: "https://wordpress.org/plugins/print-my-blog/#developers" );
	exit( 0 );
}
CPE = "cpe:/a:cmljnelson:print-my-blog";
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
if(version_is_less( version: version, test_version: "1.6.7" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "1.6.7", install_path: location );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

