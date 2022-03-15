if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.112612" );
	script_version( "2021-08-30T09:01:25+0000" );
	script_tag( name: "last_modification", value: "2021-08-30 09:01:25 +0000 (Mon, 30 Aug 2021)" );
	script_tag( name: "creation_date", value: "2019-07-22 12:36:00 +0000 (Mon, 22 Jul 2019)" );
	script_tag( name: "cvss_base", value: "9.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:C/I:C/A:C" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-03-16 09:15:00 +0000 (Mon, 16 Mar 2020)" );
	script_cve_id( "CVE-2019-10673" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_name( "WordPress Ultimate Member Plugin < 2.0.40 CSRF Vulnerability" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2019 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "gb_wordpress_plugin_http_detect.sc" );
	script_mandatory_keys( "wordpress/plugin/ultimate-member/detected" );
	script_tag( name: "summary", value: "The WordPress plugin Ultimate Member is prone to a cross-site request forgery (CSRF) vulnerability." );
	script_tag( name: "insight", value: "The vulnerability exists because the attacker can change the e-mail address in the administrator profile
  which makes him able to reset the administrator password using the WordPress 'password forget' form." );
	script_tag( name: "impact", value: "Successful exploitation of this vulnerability would allow a remote attacker
  to become admin and subsequently extract sensitive information and execute arbitrary code." );
	script_tag( name: "affected", value: "WordPress Ultimate Member plugin before version 2.0.40." );
	script_tag( name: "solution", value: "Update to version 2.0.40 or later." );
	script_xref( name: "URL", value: "https://wordpress.org/plugins/ultimate-member/#developers" );
	script_xref( name: "URL", value: "https://wpvulndb.com/vulnerabilities/9250" );
	script_xref( name: "URL", value: "https://packetstormsecurity.com/files/152315/WordPress-Ultimate-Member-2.0.38-Cross-Site-Request-Forgery.html" );
	exit( 0 );
}
CPE = "cpe:/a:ultimatemember:ultimate-member";
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
if(version_is_less( version: version, test_version: "2.0.40" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "2.0.40", install_path: location );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

