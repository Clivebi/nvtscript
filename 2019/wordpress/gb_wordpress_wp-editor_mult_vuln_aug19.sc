if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.113476" );
	script_version( "2021-08-30T10:01:19+0000" );
	script_tag( name: "last_modification", value: "2021-08-30 10:01:19 +0000 (Mon, 30 Aug 2021)" );
	script_tag( name: "creation_date", value: "2019-08-27 14:27:19 +0000 (Tue, 27 Aug 2019)" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-08-20 15:35:00 +0000 (Tue, 20 Aug 2019)" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_cve_id( "CVE-2016-10885", "CVE-2016-10886" );
	script_name( "WordPress WP Editor Plugin < 1.2.6 Multiple Vulnerabilities" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2019 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "gb_wordpress_plugin_http_detect.sc" );
	script_mandatory_keys( "wordpress/plugin/wp-editor/detected" );
	script_tag( name: "summary", value: "The WordPress plugin WP Editor is prone to multiple vulnerabilities." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "There is a CSRF vulnerability and an incorrect permissions vulnerability." );
	script_tag( name: "impact", value: "Successful exploitation would allow an attacker to perform actions in the context
  of another user or perform actions he would normally not be allowed to." );
	script_tag( name: "affected", value: "WordPress WP Editor plugin through version 1.2.5.3." );
	script_tag( name: "solution", value: "Update to version 1.2.6 or later." );
	script_xref( name: "URL", value: "https://wordpress.org/plugins/wp-editor/#developers" );
	exit( 0 );
}
CPE = "cpe:/a:benjaminrojas:wp-editor";
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
	security_message( data: report, port: port );
	exit( 0 );
}
exit( 99 );

