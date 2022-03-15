if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.112607" );
	script_version( "2020-11-10T11:45:08+0000" );
	script_tag( name: "last_modification", value: "2020-11-10 11:45:08 +0000 (Tue, 10 Nov 2020)" );
	script_tag( name: "creation_date", value: "2019-07-16 19:00:00 +0000 (Tue, 16 Jul 2019)" );
	script_tag( name: "cvss_base", value: "9.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:S/C:C/I:C/A:C" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_name( "WordPress Ad Inserter Plugin < 2.4.22 Remote Code Execution Vulnerability" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2019 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "gb_wordpress_plugin_http_detect.sc" );
	script_mandatory_keys( "wordpress/plugin/ad-inserter/detected" );
	script_tag( name: "summary", value: "The WordPress plugin Ad Inserter is prone to an authenticated remote code execution vulnerability." );
	script_tag( name: "insight", value: "The vulnerability stems from the use of the check_admin_referer() for authorization,
  when it was specifically designed to protect WordPress sites against cross-site request forgery (CSRF) exploits using nonces -
  one-time tokens used for blocking expired and repeated requests.

  Authenticated attackers who get their hands on a nonce can bypass the authorization checks powered by
  the check_admin_referer() function to access the debug mode provided by the Ad Inserter plugin.

  Once the attacker has a nonce at his disposal, he can immediately trigger the debugging feature and,
  even more dangerous, exploit the ad preview feature by sending a malicious payload containing arbitrary PHP code." );
	script_tag( name: "impact", value: "Successful exploitation would allow authenticated users (Subscribers and above)
  to execute arbitrary PHP code on websites using the plugin." );
	script_tag( name: "affected", value: "WordPress Ad Inserter plugin before version 2.4.22." );
	script_tag( name: "solution", value: "Update to version 2.4.22 or later." );
	script_xref( name: "URL", value: "https://wordpress.org/plugins/ad-inserter/#developers" );
	script_xref( name: "URL", value: "https://www.bleepingcomputer.com/news/security/critical-bug-in-wordpress-plugin-lets-hackers-execute-code/" );
	script_xref( name: "URL", value: "https://www.wordfence.com/blog/2019/07/critical-vulnerability-patched-in-ad-inserter-plugin/" );
	exit( 0 );
}
CPE = "cpe:/a:igor_funa:ad-inserter";
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
if(version_is_less( version: version, test_version: "2.1" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "2.1", install_path: location );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

