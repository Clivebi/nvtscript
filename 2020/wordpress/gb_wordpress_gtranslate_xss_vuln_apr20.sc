if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.113675" );
	script_version( "2021-07-07T02:00:46+0000" );
	script_tag( name: "last_modification", value: "2021-07-07 02:00:46 +0000 (Wed, 07 Jul 2021)" );
	script_tag( name: "creation_date", value: "2020-04-19 10:05:49 +0000 (Sun, 19 Apr 2020)" );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:P/A:N" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-05-19 14:15:00 +0000 (Tue, 19 May 2020)" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_cve_id( "CVE-2020-11930" );
	script_name( "WordPress GTranslate Plugin < 2.8.52 XSS Vulnerability" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "gb_wordpress_plugin_http_detect.sc" );
	script_mandatory_keys( "wordpress/plugin/gtranslate/detected" );
	script_tag( name: "summary", value: "The WordPress plugin GTranslate is prone to a cross-site scripting (XSS) vulnerability." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "The vulnerability is exploitable by using the hreflang tags feature
  within a sub-domain or sub-directory paid option." );
	script_tag( name: "impact", value: "Successful exploitation would allow an attacker to
  inject arbitrary HTML and JavaScroipt into the site." );
	script_tag( name: "affected", value: "WordPress GTranslate plugin through version 2.8.51." );
	script_tag( name: "solution", value: "Update to version 2.8.52 or later." );
	script_xref( name: "URL", value: "https://wordpress.org/plugins/gtranslate/#developers" );
	exit( 0 );
}
CPE = "cpe:/a:gtranslate:gtranslate";
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
if(version_is_less( version: version, test_version: "2.8.52" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "2.8.52", install_path: location );
	security_message( data: report, port: port );
	exit( 0 );
}
exit( 99 );

