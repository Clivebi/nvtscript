if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.113467" );
	script_version( "2021-08-30T10:01:19+0000" );
	script_tag( name: "last_modification", value: "2021-08-30 10:01:19 +0000 (Mon, 30 Aug 2021)" );
	script_tag( name: "creation_date", value: "2019-08-27 11:09:13 +0000 (Tue, 27 Aug 2019)" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-08-19 18:08:00 +0000 (Mon, 19 Aug 2019)" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_cve_id( "CVE-2016-10887" );
	script_name( "WordPress All In One WP Security & Firewall Plugin < 4.0.9 SQL Injection Vulnerability" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2019 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "gb_wordpress_plugin_http_detect.sc" );
	script_mandatory_keys( "wordpress/plugin/all-in-one-wp-security-and-firewall/detected" );
	script_tag( name: "summary", value: "The WordPress plugin All In One WP Security & Firewall is prone to an SQL injection vulnerability." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "impact", value: "Successful exploitation would allow an attacker to read and modify data in the database,
  and maybe even execute code on the target machine." );
	script_tag( name: "affected", value: "WordPress All In One WP Security & Firewall plugin through version 4.0.8." );
	script_tag( name: "solution", value: "Update to version 4.0.9 or later." );
	script_xref( name: "URL", value: "https://wordpress.org/plugins/all-in-one-wp-security-and-firewall/#developers" );
	exit( 0 );
}
CPE = "cpe:/a:tipsandtricks-hq:all-in-one-wp-security-and-firewall";
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
if(version_is_less( version: version, test_version: "4.0.9" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "4.0.9", install_path: location );
	security_message( data: report, port: port );
	exit( 0 );
}
exit( 99 );

