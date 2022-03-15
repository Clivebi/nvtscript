if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.112575" );
	script_version( "2021-08-30T09:01:25+0000" );
	script_tag( name: "last_modification", value: "2021-08-30 09:01:25 +0000 (Mon, 30 Aug 2021)" );
	script_tag( name: "creation_date", value: "2019-05-08 15:30:00 +0200 (Wed, 08 May 2019)" );
	script_tag( name: "cvss_base", value: "6.4" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:P/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-08-24 17:37:00 +0000 (Mon, 24 Aug 2020)" );
	script_cve_id( "CVE-2019-11807" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_name( "WordPress WooCommerce Checkout Plugin < 4.3 Unauthenticated Media Deletion Vulnerability" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2019 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "gb_wordpress_plugin_http_detect.sc" );
	script_mandatory_keys( "wordpress/plugin/woocommerce-checkout-manager/detected" );
	script_tag( name: "summary", value: "The WordPress plugin WooCommerce Checkout is prone to an unauthenticated media deletion vulnerability." );
	script_tag( name: "insight", value: "The plugin allows media deletion via the wp-admin/admin-ajax.php?action=update_attachment_wccm wccm_default_keys_load
  parameter because of a nopriv_ registration and a lack of capabilities checks." );
	script_tag( name: "affected", value: "WordPress WooCommerce Checkout plugin before version 4.3." );
	script_tag( name: "solution", value: "Update to version 4.3 or later." );
	script_xref( name: "URL", value: "https://www.wordfence.com/blog/2019/05/unauthenticated-media-deletion-vulnerability-patched-in-woocommerce-checkout-manager-plugin/" );
	script_xref( name: "URL", value: "https://wordpress.org/plugins/woocommerce-checkout-manager/#developers" );
	exit( 0 );
}
CPE = "cpe:/a:quadlayers:woocommerce-checkout-manager";
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
if(version_is_less( version: version, test_version: "4.3" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "4.3", install_path: location );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

