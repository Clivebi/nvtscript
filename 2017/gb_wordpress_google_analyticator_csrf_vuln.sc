if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.112037" );
	script_version( "2021-09-17T10:01:50+0000" );
	script_tag( name: "last_modification", value: "2021-09-17 10:01:50 +0000 (Fri, 17 Sep 2021)" );
	script_tag( name: "creation_date", value: "2017-09-11 08:11:31 +0200 (Mon, 11 Sep 2017)" );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2017-09-11 14:25:00 +0000 (Mon, 11 Sep 2017)" );
	script_cve_id( "CVE-2015-4697" );
	script_bugtraq_id( 75325 );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_name( "WordPress Google Analyticator Plugin CSRF Vulnerability" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2017 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "gb_wordpress_plugin_http_detect.sc" );
	script_mandatory_keys( "wordpress/plugin/google-analyticator/detected" );
	script_tag( name: "summary", value: "The administrative actions in WordPress Google Analyticator allowed by the plugin can be exploited using
      CSRF which could be used to disrupt the functionality provided by the
      plugin." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "affected", value: "WordPress Google Analyticator plugin before 6.4.9.4." );
	script_tag( name: "solution", value: "Update to version 6.4.9.4 or later." );
	script_xref( name: "URL", value: "https://wordpress.org/plugins/google-analyticator/#developers" );
	exit( 0 );
}
CPE = "cpe:/a:sumome:google-analyticator";
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
if(version_is_less( version: version, test_version: "6.4.9.4" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "6.4.9.4", install_path: location );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

