if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.113695" );
	script_version( "2021-07-07T02:00:46+0000" );
	script_tag( name: "last_modification", value: "2021-07-07 02:00:46 +0000 (Wed, 07 Jul 2021)" );
	script_tag( name: "creation_date", value: "2020-05-29 09:13:17 +0000 (Fri, 29 May 2020)" );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-05-28 20:00:00 +0000 (Thu, 28 May 2020)" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_cve_id( "CVE-2020-13641" );
	script_name( "WordPress Real-Time Find and Replace Plugin < 4.0.2 CSRF Vulnerability" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "gb_wordpress_plugin_http_detect.sc" );
	script_mandatory_keys( "wordpress/plugin/real-time-find-and-replace/detected" );
	script_tag( name: "summary", value: "The WordPress plugin Real-Time Find and Replace is prone to
  a cross-site request forgery (CSRF) vulnerability." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "The far_options_page function does not do any nonce verification,
  allowing for requests to be forged on behalf of an administrator. The find and replace rules
  could be updated with malicious JavaScript, allowing for that be executed later in the victims browser." );
	script_tag( name: "impact", value: "Successful exploitation would allow an attacker to
  perform actions in the context of an administrator." );
	script_tag( name: "affected", value: "WordPress Real-Time Find and Replace plugin through version 4.0.1." );
	script_tag( name: "solution", value: "Update to version 4.0.2." );
	script_xref( name: "URL", value: "https://www.wordfence.com/blog/2020/04/high-severity-vulnerability-patched-in-real-time-find-and-replace-plugin/" );
	script_xref( name: "URL", value: "https://wordpress.org/plugins/real-time-find-and-replace/#developers" );
	exit( 0 );
}
CPE = "cpe:/a:infolific:real-time-find-and-replace";
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
if(version_is_less( version: version, test_version: "4.0.2" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "4.0.2", install_path: location );
	security_message( data: report, port: port );
	exit( 0 );
}
exit( 99 );

