if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.112795" );
	script_version( "2021-07-07T02:00:46+0000" );
	script_tag( name: "last_modification", value: "2021-07-07 02:00:46 +0000 (Wed, 07 Jul 2021)" );
	script_tag( name: "creation_date", value: "2020-08-04 08:28:00 +0000 (Tue, 04 Aug 2020)" );
	script_tag( name: "cvss_base", value: "6.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:S/C:P/I:P/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-01-11 21:44:00 +0000 (Mon, 11 Jan 2021)" );
	script_cve_id( "CVE-2020-35932", "CVE-2020-35933" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_name( "WordPress Newsletter Plugin < 6.8.2 Multiple Vulnerabilities" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "gb_wordpress_plugin_http_detect.sc" );
	script_mandatory_keys( "wordpress/plugin/newsletter/detected" );
	script_tag( name: "summary", value: "The WordPress plugin Newsletter is prone to multiple vulnerabilities." );
	script_tag( name: "insight", value: "The following vulnerabilities exist:

  - Authenticated reflected cross-site-scripting (XSS) (CVE-2020-35933)

  - PHP Object Injection (CVE-2020-35932)" );
	script_tag( name: "impact", value: "Successful exploitation would decode and execute malicious JavaScript in the victim's browser
  or execute arbitrary code, upload files, or perform other tactics that could lead to site takeover." );
	script_tag( name: "affected", value: "WordPress Newsletter plugin before version 6.8.2." );
	script_tag( name: "solution", value: "Update to version 6.8.2 or later." );
	script_xref( name: "URL", value: "https://wordpress.org/plugins/newsletter/#developers" );
	script_xref( name: "URL", value: "https://www.wordfence.com/blog/2020/08/newsletter-plugin-vulnerabilities-affect-over-300000-sites/" );
	exit( 0 );
}
CPE = "cpe:/a:thenewsletterplugin:newsletter";
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
if(version_is_less( version: version, test_version: "6.8.2" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "6.8.2", install_path: location );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

