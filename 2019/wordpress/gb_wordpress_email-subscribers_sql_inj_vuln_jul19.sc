if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.112611" );
	script_version( "2021-08-30T10:01:19+0000" );
	script_tag( name: "last_modification", value: "2021-08-30 10:01:19 +0000 (Mon, 30 Aug 2021)" );
	script_tag( name: "creation_date", value: "2019-07-22 09:36:00 +0000 (Mon, 22 Jul 2019)" );
	script_tag( name: "cvss_base", value: "10.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:C/A:C" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-07-31 08:15:00 +0000 (Wed, 31 Jul 2019)" );
	script_cve_id( "CVE-2019-13569" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_name( "WordPress Email Subscribers Plugin < 4.1.8 SQL Injection Vulnerability" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2019 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "gb_wordpress_plugin_http_detect.sc" );
	script_mandatory_keys( "wordpress/plugin/email-subscribers/detected" );
	script_tag( name: "summary", value: "The WordPress plugin Email Subscribers & Newsletters is prone to an SQL injection vulnerability." );
	script_tag( name: "impact", value: "Successful exploitation of this vulnerability would allow a remote attacker
  to execute arbitrary SQL commands on the affected system." );
	script_tag( name: "affected", value: "WordPress Email Subscribers & Newsletters plugin before version 4.1.8." );
	script_tag( name: "solution", value: "Update to version 4.1.8 or later." );
	script_xref( name: "URL", value: "https://wordpress.org/plugins/email-subscribers/#developers" );
	script_xref( name: "URL", value: "https://fortiguard.com/zeroday/3016" );
	exit( 0 );
}
CPE = "cpe:/a:icegram:email-subscribers";
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
if(version_is_less( version: version, test_version: "4.1.8" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "4.1.8", install_path: location );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

