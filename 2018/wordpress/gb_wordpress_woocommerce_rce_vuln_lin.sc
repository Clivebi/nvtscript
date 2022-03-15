if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.112421" );
	script_version( "2021-07-16T12:10:35+0000" );
	script_tag( name: "cvss_base", value: "5.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:S/C:N/I:P/A:P" );
	script_tag( name: "last_modification", value: "2021-07-16 12:10:35 +0000 (Fri, 16 Jul 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-10-03 00:03:00 +0000 (Thu, 03 Oct 2019)" );
	script_tag( name: "creation_date", value: "2018-11-13 11:23:11 +0100 (Tue, 13 Nov 2018)" );
	script_cve_id( "CVE-2018-20714" );
	script_name( "WordPress WooCommerce Plugin RCE Vulnerability" );
	script_tag( name: "summary", value: "The host is installed with the WooCommerce
  Plugin for WordPress and is prone to a remote code execution vulnerability." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "A flaw in the way WordPress handles privileges can lead to a privilege escalation
  in the plugin. The vulnerability allows shop managers to delete certain files on the server and then to take over
  any administrator account." );
	script_tag( name: "affected", value: "WooCommerce plugin for WordPress prior to version 3.4.6." );
	script_tag( name: "solution", value: "Update to version 3.4.6 or later." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_xref( name: "URL", value: "https://blog.ripstech.com/2018/wordpress-design-flaw-leads-to-woocommerce-rce/" );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH" );
	script_category( ACT_GATHER_INFO );
	script_family( "Web application abuses" );
	script_dependencies( "gb_wordpress_plugin_http_detect.sc" );
	script_mandatory_keys( "wordpress/plugin/woocommerce/detected" );
	exit( 0 );
}
CPE = "cpe:/a:woocommerce:woocommerce";
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
if(version_is_less( version: version, test_version: "3.4.6" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "3.4.6", install_path: location );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

