CPE = "cpe:/a:givewp:give";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.146623" );
	script_version( "2021-09-03T13:01:29+0000" );
	script_tag( name: "last_modification", value: "2021-09-03 13:01:29 +0000 (Fri, 03 Sep 2021)" );
	script_tag( name: "creation_date", value: "2021-09-03 09:43:52 +0000 (Fri, 03 Sep 2021)" );
	script_tag( name: "cvss_base", value: "3.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:S/C:N/I:P/A:N" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:H/UI:R/S:C/C:L/I:L/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-08-26 18:42:00 +0000 (Thu, 26 Aug 2021)" );
	script_cve_id( "CVE-2021-24524" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_name( "WordPress GiveWP Plugin < 2.12.0 XSS Vulnerability" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "gb_wordpress_plugin_http_detect.sc" );
	script_mandatory_keys( "wordpress/plugin/give/detected" );
	script_tag( name: "summary", value: "The WordPress plugin GiveWP is prone to a cross-site scripting
  (XSS) vulnerability." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "The plugin does not escape the Donation Level setting of its
  Donation Forms, allowing high privilege users to use XSS payloads in them." );
	script_tag( name: "affected", value: "WordPress GiveWP plugin prior to version 2.12.0." );
	script_tag( name: "solution", value: "Update to version 2.12.0 or later." );
	script_xref( name: "URL", value: "https://wpscan.com/vulnerability/5a4774ec-c0ee-4c6b-92a6-fa10821ec336" );
	script_xref( name: "URL", value: "https://wordpress.org/plugins/give/#developers" );
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
if(version_is_less( version: version, test_version: "2.12.0" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "2.12.0", install_path: location );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

