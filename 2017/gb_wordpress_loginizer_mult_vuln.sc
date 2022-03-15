if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.140287" );
	script_version( "2021-09-15T14:07:14+0000" );
	script_tag( name: "last_modification", value: "2021-09-15 14:07:14 +0000 (Wed, 15 Sep 2021)" );
	script_tag( name: "creation_date", value: "2017-08-08 16:16:18 +0700 (Tue, 08 Aug 2017)" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2017-08-15 15:52:00 +0000 (Tue, 15 Aug 2017)" );
	script_cve_id( "CVE-2017-12650", "CVE-2017-12651" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_name( "WordPress Loginizer Plugin Multiple Vulnerabilities" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2017 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "gb_wordpress_plugin_http_detect.sc" );
	script_mandatory_keys( "wordpress/plugin/loginizer/detected" );
	script_tag( name: "summary", value: "WordPress Loginizer plugin is prone to multiple vulnerabilities." );
	script_tag( name: "insight", value: "WordPress Loginizer plugin is prone to multiple vulnerabilities:

  - SQL Injection via the X-Forwarded-For HTTP header. (CVE-2017-12650)

  - Cross Site Request Forgery (CSRF) in the Blacklist and Whitelist IP Wizard in init.php because the HTTP Referer
header is not checked. (CVE-2017-12651)" );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "affected", value: "WordPress Loginizer plugin version 1.3.5 and prior." );
	script_tag( name: "solution", value: "Update to version 1.3.6 or later." );
	script_xref( name: "URL", value: "https://sv.wordpress.org/plugins/loginizer/#developers" );
	exit( 0 );
}
CPE = "cpe:/a:raj_kothari:loginizer";
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
if(version_is_less( version: version, test_version: "1.3.6" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "1.3.6", install_path: location );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

