if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.112734" );
	script_version( "2021-07-07T02:00:46+0000" );
	script_tag( name: "last_modification", value: "2021-07-07 02:00:46 +0000 (Wed, 07 Jul 2021)" );
	script_tag( name: "creation_date", value: "2020-04-28 11:52:00 +0000 (Tue, 28 Apr 2020)" );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-04-29 17:16:00 +0000 (Wed, 29 Apr 2020)" );
	script_cve_id( "CVE-2020-12075", "CVE-2020-12076" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_name( "WordPress Data Tables Generator by Supsystic Plugin < 1.9.92 Multiple Vulnerabilities" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "gb_wordpress_plugin_http_detect.sc" );
	script_mandatory_keys( "wordpress/plugin/data-tables-generator-by-supsystic/detected" );
	script_tag( name: "summary", value: "Data Tables Generator by Supsystic plugin for WordPress is prone to multiple vulnerabilities." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "impact", value: "Successful exploitation would allow an attacker to execute several AJAX actions, inject
  malicious Javascript, and forge requests on behalf of an authenticated site user." );
	script_tag( name: "affected", value: "WordPress Data Tables Generator by Supsystic plugin before version 1.9.92." );
	script_tag( name: "solution", value: "Update to version 1.9.92 or later." );
	script_xref( name: "URL", value: "https://wordpress.org/plugins/data-tables-generator-by-supsystic/" );
	script_xref( name: "URL", value: "https://www.wordfence.com/blog/2020/03/vulnerabilities-patched-in-the-data-tables-generator-by-supsystic-plugin/" );
	exit( 0 );
}
CPE = "cpe:/a:supsystic:data-tables-generator-by-supsystic";
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
if(version_is_less( version: version, test_version: "1.9.92" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "1.9.92", install_path: location );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

