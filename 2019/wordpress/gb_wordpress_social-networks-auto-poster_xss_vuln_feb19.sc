if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.112559" );
	script_version( "2021-08-30T09:01:25+0000" );
	script_tag( name: "last_modification", value: "2021-08-30 09:01:25 +0000 (Mon, 30 Aug 2021)" );
	script_tag( name: "creation_date", value: "2019-04-01 12:45:00 +0100 (Mon, 01 Apr 2019)" );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:P/A:N" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-03-25 16:42:00 +0000 (Mon, 25 Mar 2019)" );
	script_cve_id( "CVE-2019-9911" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_name( "WordPress Social Networks Auto-Poster Plugin < 4.2.8 XSS Vulnerability" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2019 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "gb_wordpress_plugin_http_detect.sc" );
	script_mandatory_keys( "wordpress/plugin/social-networks-auto-poster-facebook-twitter-g/detected" );
	script_tag( name: "summary", value: "The WordPress plugin Social Networks Auto-Poster is prone to a cross-site scripting (XSS) vulnerability." );
	script_tag( name: "impact", value: "Successful exploitation would allow an attacker to inject malicious content into an affected site." );
	script_tag( name: "affected", value: "WordPress Social Networks Auto-Poster plugin before version 4.2.8." );
	script_tag( name: "solution", value: "Update to version 4.2.8 or later." );
	script_xref( name: "URL", value: "https://lists.openwall.net/full-disclosure/2019/02/05/12" );
	script_xref( name: "URL", value: "https://wordpress.org/plugins/social-networks-auto-poster-facebook-twitter-g/#developers" );
	exit( 0 );
}
CPE = "cpe:/a:nextscripts:social-networks-auto-poster-facebook-twitter-g";
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
if(version_is_less( version: version, test_version: "4.2.8" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "4.2.8", install_path: location );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

