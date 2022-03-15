CPE = "cpe:/a:woocommerce:woocommerce";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.145162" );
	script_version( "2021-08-17T09:01:01+0000" );
	script_tag( name: "last_modification", value: "2021-08-17 09:01:01 +0000 (Tue, 17 Aug 2021)" );
	script_tag( name: "creation_date", value: "2021-01-15 03:10:59 +0000 (Fri, 15 Jan 2021)" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:N/A:N" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-12-29 21:26:00 +0000 (Tue, 29 Dec 2020)" );
	script_cve_id( "CVE-2020-29156" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_name( "WordPress WooCommerce Plugin < 4.7.0 Information Disclosure Vulnerability" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "gb_wordpress_plugin_http_detect.sc" );
	script_mandatory_keys( "wordpress/plugin/woocommerce/detected" );
	script_tag( name: "summary", value: "The WooCommerce plugin for WordPress is prone to an information disclosure
  vulnerability." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "The WooCommerce plugin for WordPress allows remote attackers to view the
  status of arbitrary orders via the order_id parameter in a fetch_order_status action." );
	script_tag( name: "affected", value: "WooCommerce plugin prior to version 4.7.0." );
	script_tag( name: "solution", value: "Update to version 4.7.0 or later." );
	script_xref( name: "URL", value: "https://github.com/Ko-kn3t/CVE-2020-29156" );
	script_xref( name: "URL", value: "https://raw.githubusercontent.com/woocommerce/woocommerce/master/changelog.txt" );
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
if(version_is_less( version: version, test_version: "4.7.0" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "4.7.0", install_path: location );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

