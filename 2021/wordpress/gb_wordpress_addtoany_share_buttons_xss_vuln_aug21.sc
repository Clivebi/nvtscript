CPE = "cpe:/a:addtoany:addtoany_share_buttons";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.146809" );
	script_version( "2021-09-30T13:01:29+0000" );
	script_tag( name: "last_modification", value: "2021-09-30 13:01:29 +0000 (Thu, 30 Sep 2021)" );
	script_tag( name: "creation_date", value: "2021-09-30 09:22:48 +0000 (Thu, 30 Sep 2021)" );
	script_tag( name: "cvss_base", value: "3.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:S/C:N/I:P/A:N" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:L/UI:R/S:C/C:L/I:L/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-09-09 21:08:00 +0000 (Thu, 09 Sep 2021)" );
	script_cve_id( "CVE-2021-24568" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_name( "WordPress AddToAny Share Buttons Plugin < 1.7.46 XSS Vulnerability" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "gb_wordpress_plugin_http_detect.sc" );
	script_mandatory_keys( "wordpress/plugin/add-to-any/detected" );
	script_tag( name: "summary", value: "The WordPress plugin AddToAny Share Buttons is prone to a
  cross-site scripting (XSS) vulnerability." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "The plugin does not sanitise its Sharing Header setting when
  outputting it in frontend pages, allowing high privilege users such as admin to perform XSS
  attacks even when the unfiltered_html capability is disallowed." );
	script_tag( name: "affected", value: "WordPress AddToAny Share Buttons through version 1.7.45." );
	script_tag( name: "solution", value: "Update to version 1.7.46 or later." );
	script_xref( name: "URL", value: "https://wpscan.com/vulnerability/cf7c0207-adb2-44c6-9469-2b24dbfec83a" );
	script_xref( name: "URL", value: "https://wordpress.org/plugins/add-to-any/#developers" );
	exit( 0 );
}
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
if(version_is_less( version: version, test_version: "1.7.46" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "1.7.46", install_path: location );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

