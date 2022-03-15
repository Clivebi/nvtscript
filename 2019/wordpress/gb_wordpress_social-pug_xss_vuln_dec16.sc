if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.112531" );
	script_version( "2021-08-30T10:01:19+0000" );
	script_tag( name: "last_modification", value: "2021-08-30 10:01:19 +0000 (Mon, 30 Aug 2021)" );
	script_tag( name: "creation_date", value: "2019-03-06 10:44:00 +0100 (Wed, 06 Mar 2019)" );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:P/A:N" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-01-15 15:26:00 +0000 (Tue, 15 Jan 2019)" );
	script_cve_id( "CVE-2016-10736" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_name( "WordPress Social Pug Plugin < 1.2.6 XSS Vulnerability" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2019 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "gb_wordpress_plugin_http_detect.sc" );
	script_mandatory_keys( "wordpress/plugin/social-pug/detected" );
	script_tag( name: "summary", value: "The WordPress plugin Social Pug is prone to a cross-site scripting vulnerability." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "affected", value: "WordPress Social Pug plugin before version 1.2.6." );
	script_tag( name: "solution", value: "Update to version 1.2.6 or later." );
	script_xref( name: "URL", value: "https://wordpress.org/plugins/social-pug/#developers" );
	script_xref( name: "URL", value: "https://advisories.dxw.com/advisories/reflected-xss-in-social-pug-easy-social-share-buttons-could-allow-an-attacker-to-do-almost-anything-an-admin-user-can/" );
	exit( 0 );
}
CPE = "cpe:/a:mediavine:social-pug";
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
if(version_is_less( version: version, test_version: "1.2.6" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "1.2.6", install_path: location );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

