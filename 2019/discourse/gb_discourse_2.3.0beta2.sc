CPE = "cpe:/a:discourse:discourse";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.108596" );
	script_version( "2019-08-28T09:18:40+0000" );
	script_tag( name: "last_modification", value: "2019-08-28 09:18:40 +0000 (Wed, 28 Aug 2019)" );
	script_tag( name: "creation_date", value: "2019-06-17 06:03:35 +0000 (Mon, 17 Jun 2019)" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:N/A:N" );
	script_name( "Discourse < 2.3.0.beta2 XSS Vulnerability" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2019 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "gb_discourse_detect.sc" );
	script_mandatory_keys( "discourse/detected" );
	script_tag( name: "summary", value: "Discourse is prone to a cross-site scripting vulnerability in dashboard report tables." );
	script_tag( name: "affected", value: "Discourse before version 2.3.0.beta2." );
	script_tag( name: "solution", value: "Update to version 2.3.0.beta2." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_xref( name: "URL", value: "https://meta.discourse.org/t/discourse-2-3-0-beta2-release-notes/108690" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_tag( name: "solution_type", value: "VendorFix" );
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
vers = infos["version"];
if(version_is_less( version: vers, test_version: "2.3.0" ) || version_is_equal( version: vers, test_version: "2.3.0.beta1" )){
	report = report_fixed_ver( installed_version: vers, fixed_version: "2.3.0.beta2", install_path: infos["location"] );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

