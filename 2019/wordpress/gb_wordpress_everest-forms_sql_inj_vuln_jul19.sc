if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.112609" );
	script_version( "2021-08-30T10:01:19+0000" );
	script_tag( name: "last_modification", value: "2021-08-30 10:01:19 +0000 (Mon, 30 Aug 2021)" );
	script_tag( name: "creation_date", value: "2019-07-19 09:16:00 +0000 (Fri, 19 Jul 2019)" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-07-19 23:15:00 +0000 (Fri, 19 Jul 2019)" );
	script_cve_id( "CVE-2019-13575" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_name( "WordPress Everest Forms Plugin < 1.5.0 SQL Injection Vulnerability" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2019 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "gb_wordpress_plugin_http_detect.sc" );
	script_mandatory_keys( "wordpress/plugin/everest-forms/detected" );
	script_tag( name: "summary", value: "The WordPress plugin Everest Forms is prone to an SQL injection vulnerability." );
	script_tag( name: "impact", value: "Successful exploitation of this vulnerability would allow a remote attacker
  to execute arbitrary SQL commands on the affected system." );
	script_tag( name: "affected", value: "WordPress Everest Forms plugin before version 1.5.0." );
	script_tag( name: "solution", value: "Update to version 1.5.0 or later." );
	script_xref( name: "URL", value: "https://wordpress.org/plugins/everest-forms/#developers" );
	script_xref( name: "URL", value: "https://wpvulndb.com/vulnerabilities/9466" );
	script_xref( name: "URL", value: "https://github.com/wpeverest/everest-forms/commit/755d095fe0d9a756a13800d1513cf98219e4a3f9#diff-bb2b21ef7774df8687ff02b0284505c6" );
	exit( 0 );
}
CPE = "cpe:/a:wpeverest:everest-forms";
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
if(version_is_less( version: version, test_version: "1.5.0" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "1.5.0", install_path: location );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

