if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.112294" );
	script_version( "2021-08-30T09:01:25+0000" );
	script_tag( name: "last_modification", value: "2021-08-30 09:01:25 +0000 (Mon, 30 Aug 2021)" );
	script_tag( name: "creation_date", value: "2019-06-20 14:40:00 +0200 (Thu, 20 Jun 2019)" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-08-24 17:37:00 +0000 (Mon, 24 Aug 2020)" );
	script_cve_id( "CVE-2018-16613" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_name( "WordPress wpForo Forum Plugin < 1.5.2 Privilege Escalation Vulnerability" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2019 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "gb_wordpress_plugin_http_detect.sc" );
	script_mandatory_keys( "wordpress/plugin/wpforo/detected" );
	script_tag( name: "summary", value: "The WordPress plugin wpForo Forum is prone to a privilege escalation vulnerability." );
	script_tag( name: "insight", value: "The plugin suffers from a privilege escalation vulnerability,
  whereby any registered forum user can escalate his privilege to become the forum administrator without any form of user interaction." );
	script_tag( name: "affected", value: "WordPress wpForo Forum plugin before version 1.5.2." );
	script_tag( name: "solution", value: "Update to version 1.5.2 or later." );
	script_xref( name: "URL", value: "https://github.com/9emin1/advisories/blob/master/wpForo-1-5-1.md" );
	script_xref( name: "URL", value: "https://wpforo.com/community/wpforo-announcements/wpforo-1-5-2-is-released/" );
	script_xref( name: "URL", value: "https://wordpress.org/plugins/wpforo/#developers" );
	exit( 0 );
}
CPE = "cpe:/a:gvectors:wpforo";
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
if(version_is_less( version: version, test_version: "1.5.2" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "1.5.2", install_path: location );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

