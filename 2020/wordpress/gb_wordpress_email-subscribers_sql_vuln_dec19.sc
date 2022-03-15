if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.108745" );
	script_version( "2020-08-06T13:39:56+0000" );
	script_tag( name: "last_modification", value: "2020-08-06 13:39:56 +0000 (Thu, 06 Aug 2020)" );
	script_tag( name: "creation_date", value: "2020-04-09 06:19:28 +0000 (Thu, 09 Apr 2020)" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_name( "WordPress Email Subscribers Plugin < 4.3.1 Blind SQL Injection Vulnerability" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "gb_wordpress_plugin_http_detect.sc" );
	script_mandatory_keys( "wordpress/plugin/email-subscribers/detected" );
	script_tag( name: "summary", value: "The WordPress plugin Email Subscribers & Newsletters is prone to a
  blind SQL injection vulnerability." );
	script_tag( name: "impact", value: "Successful exploitation of this vulnerability would allow a remote attacker
  to execute arbitrary SQL commands on the affected system." );
	script_tag( name: "affected", value: "WordPress Email Subscribers & Newsletters plugin before version 4.3.1." );
	script_tag( name: "solution", value: "Update to version 4.3.1 or later." );
	script_xref( name: "URL", value: "https://wordpress.org/plugins/email-subscribers/#developers" );
	script_xref( name: "URL", value: "https://www.wordfence.com/blog/2019/11/multiple-vulnerabilities-patched-in-email-subscribers-newsletters-plugin/" );
	exit( 0 );
}
CPE = "cpe:/a:icegram:email-subscribers";
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
if(version_is_less( version: version, test_version: "4.3.1" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "4.3.1", install_path: location );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

