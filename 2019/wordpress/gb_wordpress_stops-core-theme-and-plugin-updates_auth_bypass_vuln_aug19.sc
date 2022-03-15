if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.113517" );
	script_version( "2021-08-30T10:01:19+0000" );
	script_tag( name: "last_modification", value: "2021-08-30 10:01:19 +0000 (Mon, 30 Aug 2021)" );
	script_tag( name: "creation_date", value: "2019-09-16 11:04:39 +0000 (Mon, 16 Sep 2019)" );
	script_tag( name: "cvss_base", value: "4.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:S/C:N/I:P/A:N" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:L/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-08-24 17:37:00 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_cve_id( "CVE-2019-15650" );
	script_name( "WordPress Easy Updates Manager Plugin < 8.0.5 Authentication Bypass Vulnerability" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2019 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "gb_wordpress_plugin_http_detect.sc" );
	script_mandatory_keys( "wordpress/plugin/stops-core-theme-and-plugin-updates/detected" );
	script_tag( name: "summary", value: "The WordPress plugin Easy Updates Manager is prone to an authentication bypass vulnerability." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "There are insufficient restrictions on options changes
  (such as disabling unattended theme updates) because of a nonce check error." );
	script_tag( name: "impact", value: "Successful exploitation would allow an authenticated attacker to
  perform actions without having the necessary authorization." );
	script_tag( name: "affected", value: "WordPress Easy Updates Manager plugin through version 8.0.4." );
	script_tag( name: "solution", value: "Update to version 8.0.5." );
	script_xref( name: "URL", value: "https://wpvulndb.com/vulnerabilities/9837" );
	script_xref( name: "URL", value: "https://wordpress.org/plugins/stops-core-theme-and-plugin-updates/#developers" );
	exit( 0 );
}
CPE = "cpe:/a:easyupdatesmanager:stops-core-theme-and-plugin-updates";
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
if(version_is_less( version: version, test_version: "8.0.5" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "8.0.5", install_path: location );
	security_message( data: report, port: port );
	exit( 0 );
}
exit( 99 );

