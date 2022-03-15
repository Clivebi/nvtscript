if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.113396" );
	script_version( "2021-08-30T10:01:19+0000" );
	script_tag( name: "last_modification", value: "2021-08-30 10:01:19 +0000 (Mon, 30 Aug 2021)" );
	script_tag( name: "creation_date", value: "2019-05-22 14:32:00 +0200 (Wed, 22 May 2019)" );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-05-15 03:29:00 +0000 (Wed, 15 May 2019)" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_cve_id( "CVE-2019-11886" );
	script_name( "WordPress WaspThemes Visual CSS Style Editor Plugin < 7.2.1 CSRF Vulnerability" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2019 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "gb_wordpress_plugin_http_detect.sc" );
	script_mandatory_keys( "wordpress/plugin/yellow-pencil-visual-theme-customizer/detected" );
	script_tag( name: "summary", value: "The WordPress plugin WaspThemes Visual CSS Style Editor
  (aka yellow-pencil-visual-theme-customizer) is prone to a cross-site request forgery (CSRF) vulnerability." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target system." );
	script_tag( name: "insight", value: "The vulnerability exists within yp_option_update." );
	script_tag( name: "impact", value: "Successful exploitation could allow an attacker to gain admin access
  via yp_remote_get." );
	script_tag( name: "affected", value: "WaspThemes Visual CSS Style Editor through version 7.2.0." );
	script_tag( name: "solution", value: "Update to version 7.2.1." );
	script_xref( name: "URL", value: "https://www.pluginvulnerabilities.com/2019/04/09/recently-closed-visual-css-style-editor-wordpress-plugin-contains-privilege-escalation-vulnerability-that-leads-to-option-update-vulnerability/" );
	script_xref( name: "URL", value: "https://www.wordfence.com/blog/2019/04/zero-day-vulnerability-in-yellow-pencil-visual-theme-customizer-exploited-in-the-wild/" );
	script_xref( name: "URL", value: "https://wpvulndb.com/vulnerabilities/9256" );
	script_xref( name: "URL", value: "https://wordpress.org/plugins/yellow-pencil-visual-theme-customizer/#developers" );
	exit( 0 );
}
CPE = "cpe:/a:waspthemese:yellow-pencil-visual-theme-customizer";
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
if(version_is_less( version: version, test_version: "7.2.1" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "7.2.1", install_path: location );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

