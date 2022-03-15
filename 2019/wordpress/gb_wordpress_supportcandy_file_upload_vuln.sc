if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.113376" );
	script_version( "2021-08-30T10:01:19+0000" );
	script_tag( name: "last_modification", value: "2021-08-30 10:01:19 +0000 (Mon, 30 Aug 2021)" );
	script_tag( name: "creation_date", value: "2019-04-24 14:46:44 +0200 (Wed, 24 Apr 2019)" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-08-01 20:15:00 +0000 (Thu, 01 Aug 2019)" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_cve_id( "CVE-2019-11223" );
	script_name( "WordPress SupportCandy Plugin <= 2.0.0 Arbitrary File Upload Vulnerability" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2019 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "gb_wordpress_plugin_http_detect.sc" );
	script_mandatory_keys( "wordpress/plugin/supportcandy/detected" );
	script_tag( name: "summary", value: "The WordPress plugin SupportCandy is prone to a file upload vulnerability." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "The plugin allows an attacker to upload arbitrary files. If the uploaded
  file has an executable extension, the file will be executed in the context of the user account
  that runs the web server hosting the affected application." );
	script_tag( name: "impact", value: "Successful exploitation would allow an attacker to execute arbitrary
  code on the target machine." );
	script_tag( name: "affected", value: "WordPress plugin SupportCandy through version 2.0.0." );
	script_tag( name: "solution", value: "Update to version 2.0.1." );
	script_xref( name: "URL", value: "https://www.pluginvulnerabilities.com/2019/04/05/arbitrary-file-upload-vulnerability-in-supportcandy/" );
	script_xref( name: "URL", value: "https://wordpress.org/plugins/supportcandy/#developers" );
	exit( 0 );
}
CPE = "cpe:/a:supportcandy:supportcandy";
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
if(version_is_less( version: version, test_version: "2.0.1" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "2.0.1", install_path: location );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

