if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.113530" );
	script_version( "2021-08-30T09:01:25+0000" );
	script_tag( name: "last_modification", value: "2021-08-30 09:01:25 +0000 (Mon, 30 Aug 2021)" );
	script_tag( name: "creation_date", value: "2019-09-16 14:59:04 +0000 (Mon, 16 Sep 2019)" );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:P/A:N" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-09-04 16:58:00 +0000 (Wed, 04 Sep 2019)" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_cve_id( "CVE-2019-15109" );
	script_name( "WordPress The Events Calendar Plugin < 4.8.2 XSS Vulnerability" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2019 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "gb_wordpress_plugin_http_detect.sc" );
	script_mandatory_keys( "wordpress/plugin/the-events-calendar/detected" );
	script_tag( name: "summary", value: "The WordPress plugin The Events Calendar is prone
  to a cross-site scripting (XSS) vulnerability." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "The vulnerability is exploitable via the tribe_paged URL parameter." );
	script_tag( name: "impact", value: "Successful exploitation would allow an attacker to
  inject arbitrary HTML and JavaScript into the site." );
	script_tag( name: "affected", value: "WordPress The Events Calendar plugin through version 4.8.1." );
	script_tag( name: "solution", value: "Update to version 4.8.2 or later." );
	script_xref( name: "URL", value: "https://wpvulndb.com/vulnerabilities/9554" );
	script_xref( name: "URL", value: "https://wordpress.org/plugins/the-events-calendar/#developers" );
	exit( 0 );
}
CPE = "cpe:/a:modern_tribe:the-events-calendar";
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
if(version_is_less( version: version, test_version: "4.8.2" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "4.8.2", install_path: location );
	security_message( data: report, port: port );
	exit( 0 );
}
exit( 99 );

