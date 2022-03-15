if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.112735" );
	script_version( "2021-07-07T02:00:46+0000" );
	script_tag( name: "last_modification", value: "2021-07-07 02:00:46 +0000 (Wed, 07 Jul 2021)" );
	script_tag( name: "creation_date", value: "2020-04-28 11:52:00 +0000 (Tue, 28 Apr 2020)" );
	script_tag( name: "cvss_base", value: "6.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:S/C:P/I:P/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-04-28 19:49:00 +0000 (Tue, 28 Apr 2020)" );
	script_cve_id( "CVE-2020-12077" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_name( "WordPress MapPress Plugin < 2.53.9 Multiple Vulnerabilities" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "gb_wordpress_plugin_http_detect.sc" );
	script_mandatory_keys( "wordpress/plugin/mappress-google-maps-for-wordpress/detected" );
	script_tag( name: "summary", value: "MapPress plugin for WordPress is prone to multiple vulnerabilities." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "One vulnerability that allowed stored Cross-Site Scripting (XSS)
  is present in both the free and pro versions of the plugin, while a far more critical vulnerability
  that allowed Remote Code Execution (RCE) is present in the pro version." );
	script_tag( name: "impact", value: "The XSS vulnerability could redirect a site visitor to a malicious site,
  or even use an administrator's session to take over the site by adding a malicious administrative user.

  The RCE vulnerability would allow an authenticated attacker with minimal permissions to upload an executable
  PHP file such as a backdoor or webshell. This could easily lead to complete site takeover, as an attacker
  with backdoor access could then modify any file on the site, upload additional files, or connect to the
  database and insert an administrative user." );
	script_tag( name: "affected", value: "WordPress MapPress plugin before version 2.53.9." );
	script_tag( name: "solution", value: "Update to version 2.53.9 or later." );
	script_xref( name: "URL", value: "https://wordpress.org/plugins/mappress-google-maps-for-wordpress/#developers" );
	script_xref( name: "URL", value: "https://www.wordfence.com/blog/2020/04/critical-vulnerabilities-patched-in-mappress-maps-plugin/" );
	exit( 0 );
}
CPE = "cpe:/a:chrisvrichardson:mappress-google-maps-for-wordpress";
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
if(version_is_less( version: version, test_version: "2.53.9" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "2.53.9", install_path: location );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

