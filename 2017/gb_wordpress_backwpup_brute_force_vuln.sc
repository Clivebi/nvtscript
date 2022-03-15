if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.112061" );
	script_version( "2021-09-14T08:01:37+0000" );
	script_tag( name: "last_modification", value: "2021-09-14 08:01:37 +0000 (Tue, 14 Sep 2021)" );
	script_tag( name: "creation_date", value: "2017-09-29 09:03:31 +0200 (Fri, 29 Sep 2017)" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:N/A:N" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2017-10-10 11:52:00 +0000 (Tue, 10 Oct 2017)" );
	script_cve_id( "CVE-2017-2551" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_name( "WordPress BackWPup Plugin Brute Force Vulnerability" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2017 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "gb_wordpress_plugin_http_detect.sc" );
	script_mandatory_keys( "wordpress/plugin/backwpup/detected" );
	script_tag( name: "summary", value: "WordPress plugin BackWPup allows possible brute forcing of backup file for download." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "affected", value: "WordPress BackWPup plugin before version 3.4.2." );
	script_tag( name: "solution", value: "Update to version 3.4.2 or later." );
	script_xref( name: "URL", value: "http://www.vapidlabs.com/advisory.php?v=201" );
	script_xref( name: "URL", value: "https://wordpress.org/plugins/backwpup/#developers" );
	exit( 0 );
}
CPE = "cpe:/a:inpsyde:backwpup";
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
if(version_is_less( version: version, test_version: "3.4.2" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "3.4.2", install_path: location );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

