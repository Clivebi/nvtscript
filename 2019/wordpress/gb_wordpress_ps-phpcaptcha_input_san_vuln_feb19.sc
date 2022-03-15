if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.112534" );
	script_version( "2021-08-30T09:01:25+0000" );
	script_tag( name: "last_modification", value: "2021-08-30 09:01:25 +0000 (Mon, 30 Aug 2021)" );
	script_tag( name: "creation_date", value: "2019-03-06 12:00:00 +0100 (Wed, 06 Mar 2019)" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-04-12 17:22:00 +0000 (Fri, 12 Apr 2019)" );
	script_cve_id( "CVE-2019-7412" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_name( "WordPress PS PHPCaptcha Plugin < 1.2.0 Input Sanitization Vulnerabilities" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2019 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "gb_wordpress_plugin_http_detect.sc" );
	script_mandatory_keys( "wordpress/plugin/ps-phpcaptcha/detected" );
	script_tag( name: "summary", value: "The WordPress plugin PS PHPCaptcha mishandles sanitization of input values." );
	script_tag( name: "affected", value: "WordPress PS PHPCaptcha plugin before version 1.2.0." );
	script_tag( name: "solution", value: "Update to version 1.2.0." );
	script_xref( name: "URL", value: "https://wordpress.org/plugins/ps-phpcaptcha/#developers" );
	script_xref( name: "URL", value: "https://www.exploit-db.com/exploits/45809" );
	exit( 0 );
}
CPE = "cpe:/a:peter_stimpel:ps-phpcaptcha";
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
if(version_is_less( version: version, test_version: "1.2.0" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "1.2.0", install_path: location );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

