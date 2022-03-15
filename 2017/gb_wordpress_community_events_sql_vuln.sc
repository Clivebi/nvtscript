if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.112038" );
	script_version( "2021-09-17T10:01:50+0000" );
	script_tag( name: "last_modification", value: "2021-09-17 10:01:50 +0000 (Fri, 17 Sep 2021)" );
	script_tag( name: "creation_date", value: "2017-09-11 08:15:31 +0200 (Mon, 11 Sep 2017)" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2017-09-11 13:55:00 +0000 (Mon, 11 Sep 2017)" );
	script_cve_id( "CVE-2015-3313" );
	script_bugtraq_id( 74234 );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_name( "WordPress Community Events Plugin SQL Vulnerability" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2017 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "gb_wordpress_plugin_http_detect.sc" );
	script_mandatory_keys( "wordpress/plugin/community-events/detected" );
	script_tag( name: "summary", value: "WordPress plugin Community Events is prone to a SQL injection vulnerability." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "affected", value: "WordPress Community Events plugin before 1.4." );
	script_tag( name: "solution", value: "Update to version 1.4 or later." );
	script_xref( name: "URL", value: "https://wordpress.org/plugins/community-events/#developers" );
	exit( 0 );
}
CPE = "cpe:/a:ylefebvre:community-events";
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
if(version_is_less( version: version, test_version: "1.4" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "1.4", install_path: location );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

