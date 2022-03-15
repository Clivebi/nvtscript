if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.113494" );
	script_version( "2021-08-30T09:01:25+0000" );
	script_tag( name: "last_modification", value: "2021-08-30 09:01:25 +0000 (Mon, 30 Aug 2021)" );
	script_tag( name: "creation_date", value: "2019-09-04 13:04:50 +0000 (Wed, 04 Sep 2019)" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:P/A:N" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-08-24 17:37:00 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_cve_id( "CVE-2019-15821" );
	script_name( "WordPress Bold Page Builder Plugin < 2.3.2 Authentication Bypass Vulnerability" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2019 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "gb_wordpress_plugin_http_detect.sc" );
	script_mandatory_keys( "wordpress/plugin/bold-page-builder/detected" );
	script_tag( name: "summary", value: "The WordPress plugin Bold Page Builder is prone to an authentication bypass vulnerability." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "There is no protection against modifying settings and importing data." );
	script_tag( name: "affected", value: "WordPress Bold Page Builder plugin through version 2.3.1." );
	script_tag( name: "solution", value: "Update to version 2.3.2 or later." );
	script_xref( name: "URL", value: "https://wpvulndb.com/vulnerabilities/9703" );
	script_xref( name: "URL", value: "https://blog.nintechnet.com/critical-vulnerability-in-wordpress-bold-page-builder-plugin-currently-being-exploited/" );
	script_xref( name: "URL", value: "https://wordpress.org/plugins/bold-page-builder/#developers" );
	exit( 0 );
}
CPE = "cpe:/a:bold-themes:bold-page-builder";
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
if(version_is_less( version: version, test_version: "2.3.2" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "2.3.2", install_path: location );
	security_message( data: report, port: port );
	exit( 0 );
}
exit( 99 );

