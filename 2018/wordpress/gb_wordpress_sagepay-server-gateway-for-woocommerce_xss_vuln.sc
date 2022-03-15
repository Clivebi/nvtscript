if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.112425" );
	script_version( "2021-05-27T06:00:15+0200" );
	script_tag( name: "last_modification", value: "2021-05-27 06:00:15 +0200 (Thu, 27 May 2021)" );
	script_tag( name: "creation_date", value: "2018-11-13 12:33:00 +0100 (Tue, 13 Nov 2018)" );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:P/A:N" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2018-01-31 15:44:00 +0000 (Wed, 31 Jan 2018)" );
	script_cve_id( "CVE-2018-5316" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_name( "WordPress SagePay Server Gateway for WooCommerce plugin < 1.0.9 XSS Vulnerability" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "gb_wordpress_plugin_http_detect.sc" );
	script_mandatory_keys( "wordpress/plugin/sagepay-server-gateway-for-woocommerce/detected" );
	script_tag( name: "summary", value: "SagePay Server Gateway for WooCommerce plugin for WordPress is prone to a cross-site scripting (XSS) vulnerability." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "affected", value: "WordPress SagePay Server Gateway for WooCommerce plugin before version 1.0.9." );
	script_tag( name: "solution", value: "Update the plugin to version 1.0.9 or later." );
	script_xref( name: "URL", value: "https://packetstormsecurity.com/files/145459/WordPress-Sagepay-Server-Gateway-For-WooCommerce-1.0.7-XSS.html" );
	script_xref( name: "URL", value: "https://wordpress.org/plugins/sagepay-server-gateway-for-woocommerce/#developers" );
	script_xref( name: "URL", value: "https://wordpress.org/support/topic/sagepay-server-gateway-for-woocommerce-1-0-7-cross-site-scripting/#post-9792337" );
	exit( 0 );
}
CPE = "cpe:/a:patsatech:sagepay-server-gateway-for-woocommerce";
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
if(version_is_less( version: version, test_version: "1.0.9" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "1.0.9", install_path: location );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

