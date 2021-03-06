if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.112066" );
	script_version( "2021-09-09T13:03:05+0000" );
	script_tag( name: "last_modification", value: "2021-09-09 13:03:05 +0000 (Thu, 09 Sep 2021)" );
	script_tag( name: "creation_date", value: "2017-10-06 09:21:51 +0200 (Fri, 06 Oct 2017)" );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:P/A:N" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2017-06-16 14:36:00 +0000 (Fri, 16 Jun 2017)" );
	script_cve_id( "CVE-2017-2187" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_name( "WordPress WP Live Chat Support Plugin XSS Vulnerability" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2017 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "gb_wordpress_plugin_http_detect.sc" );
	script_mandatory_keys( "wordpress/plugin/wp-live-chat-support/detected" );
	script_tag( name: "summary", value: "WordPress plugin WP Live Chat Support is vulnerable to cross-site scripting (XSS) resulting in
  attackers being able to inject arbitrary web script or HTML via unspecified vectors." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "affected", value: "WordPress WP Live Chat Support plugin version 7.0.06 and prior." );
	script_tag( name: "solution", value: "Update to version 7.0.07 or later." );
	script_xref( name: "URL", value: "https://wordpress.org/plugins/wp-live-chat-support/#developers" );
	exit( 0 );
}
CPE = "cpe:/a:3cx:wp-live-chat-support";
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
if(version_is_less( version: version, test_version: "7.0.07" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "7.0.07", install_path: location );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

