if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.112613" );
	script_version( "2021-08-30T10:01:19+0000" );
	script_tag( name: "last_modification", value: "2021-08-30 10:01:19 +0000 (Mon, 30 Aug 2021)" );
	script_tag( name: "creation_date", value: "2019-07-29 10:03:00 +0000 (Mon, 29 Jul 2019)" );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-08-05 17:55:00 +0000 (Mon, 05 Aug 2019)" );
	script_cve_id( "CVE-2019-14328" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_name( "WordPress Simple Membership Plugin < 3.8.5 CSRF Vulnerability" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2019 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "gb_wordpress_plugin_http_detect.sc" );
	script_mandatory_keys( "wordpress/plugin/simple-membership/detected" );
	script_tag( name: "summary", value: "The WordPress plugin Simple Membership is prone to a cross-site request forgery (CSRF) vulnerability." );
	script_tag( name: "impact", value: "Successful exploitation of this vulnerability would allow a remote attacker
  to extract sensitive information and execute arbitrary code." );
	script_tag( name: "affected", value: "WordPress Simple Membership plugin before version 3.8.5." );
	script_tag( name: "solution", value: "Update to version 3.8.5 or later." );
	script_xref( name: "URL", value: "https://wordpress.org/plugins/simple-membership/#developers" );
	exit( 0 );
}
CPE = "cpe:/a:wp_insider:simple-membership";
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
if(version_is_less( version: version, test_version: "3.8.5" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "3.8.5", install_path: location );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );
