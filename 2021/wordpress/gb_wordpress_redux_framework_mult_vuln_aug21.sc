CPE = "cpe:/a:redux:gutenberg_template_library_%26_redux_framework";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.146810" );
	script_version( "2021-09-30T13:01:29+0000" );
	script_tag( name: "last_modification", value: "2021-09-30 13:01:29 +0000 (Thu, 30 Sep 2021)" );
	script_tag( name: "creation_date", value: "2021-09-30 09:35:44 +0000 (Thu, 30 Sep 2021)" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:N/A:N" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-09-10 19:03:00 +0000 (Fri, 10 Sep 2021)" );
	script_cve_id( "CVE-2021-38312", "CVE-2021-38314" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_name( "WordPress Gutenberg Template Library & Redux Framework Plugin < 4.2.13 Multiple Vulnerabilities" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "gb_wordpress_plugin_http_detect.sc" );
	script_mandatory_keys( "wordpress/plugin/redux-framework/detected" );
	script_tag( name: "summary", value: "The WordPress plugin Gutenberg Template Library & Redux
  Framework is prone to multiple vulnerabilities." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "The following vulnerabilities exist:

  - CVE-2021-38312: Incorrect authorization leading to arbitrary plugin installation and post deletion

  - CVE-2021-38314: Unauthenticated sensitive information disclosure" );
	script_tag( name: "affected", value: "WordPress Gutenberg Template Library & Redux Framework through
  version 4.2.11." );
	script_tag( name: "solution", value: "Update to version 4.2.13 or later." );
	script_xref( name: "URL", value: "https://www.wordfence.com/blog/2021/09/over-1-million-sites-affected-by-redux-framework-vulnerabilities/" );
	script_xref( name: "URL", value: "https://wordpress.org/plugins/redux-framework/#developers" );
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
if(version_is_less_equal( version: version, test_version: "4.2.11" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "4.2.13", install_path: location );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

