CPE = "cpe:/a:cleantalk:cleantalk-spam-protect";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.112889" );
	script_version( "2021-08-17T12:00:57+0000" );
	script_tag( name: "last_modification", value: "2021-08-17 12:00:57 +0000 (Tue, 17 Aug 2021)" );
	script_tag( name: "creation_date", value: "2021-05-10 11:49:11 +0000 (Mon, 10 May 2021)" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:N/A:N" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-05-24 19:08:00 +0000 (Mon, 24 May 2021)" );
	script_cve_id( "CVE-2021-24295" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_name( "WordPress CleanTalk Plugin < 5.153.4 SQLi Vulnerability" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "gb_wordpress_plugin_http_detect.sc" );
	script_mandatory_keys( "wordpress/plugin/cleantalk-spam-protect/detected" );
	script_tag( name: "summary", value: "The WordPress CleanTalk plugin is prone to an
  SQL injection (SQLi) vulnerability." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "The update_log function in lib/Cleantalk/ApbctWP/Firewall/SFW.php,
  which is being used to insert records of requests into the database, fails to use a prepared SQL statement,
  thus leading to SQLi." );
	script_tag( name: "affected", value: "WordPress CleanTalk plugin before version 5.153.4." );
	script_tag( name: "solution", value: "Update to version 5.153.4 or later." );
	script_xref( name: "URL", value: "https://www.wordfence.com/blog/2021/05/sql-injection-vulnerability-patched-in-cleantalk-antispam-plugin/" );
	script_xref( name: "URL", value: "https://wordpress.org/plugins/cleantalk-spam-protect/#developers" );
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
if(version_is_less( version: version, test_version: "5.153.4" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "5.153.4", install_path: location );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

