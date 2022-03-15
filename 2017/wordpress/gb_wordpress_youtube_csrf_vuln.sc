if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.140536" );
	script_version( "2021-09-09T10:07:02+0000" );
	script_tag( name: "last_modification", value: "2021-09-09 10:07:02 +0000 (Thu, 09 Sep 2021)" );
	script_tag( name: "creation_date", value: "2017-11-24 13:51:43 +0700 (Fri, 24 Nov 2017)" );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:P/A:N" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:H/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2017-12-03 15:58:00 +0000 (Sun, 03 Dec 2017)" );
	script_cve_id( "CVE-2017-1000224" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_name( "WordPress YouTube Plugin CSRF Vulnerability" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2017 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "gb_wordpress_plugin_http_detect.sc" );
	script_mandatory_keys( "wordpress/plugin/youtube-embed-plus/detected" );
	script_tag( name: "summary", value: "WordPress YouTube plugin is prone to a CSRF vulnerability." );
	script_tag( name: "insight", value: "CSRF in YouTube (WordPress plugin) could allow unauthenticated attacker to
change any setting within the plugin" );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "affected", value: "WordPress YouTube plugin version 11.8.1 and prior." );
	script_tag( name: "solution", value: "Update to version 11.8.2 or later." );
	script_xref( name: "URL", value: "https://security.dxw.com/advisories/csrf-in-youtube-plugin/" );
	exit( 0 );
}
CPE = "cpe:/a:embedplus:youtube-embed-plus";
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
if(version_is_less( version: version, test_version: "11.8.2" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "11.8.2", install_path: location );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

