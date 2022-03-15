if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.112448" );
	script_version( "2021-05-27T06:00:15+0200" );
	script_tag( name: "last_modification", value: "2021-05-27 06:00:15 +0200 (Thu, 27 May 2021)" );
	script_tag( name: "creation_date", value: "2018-02-22 11:00:00 +0100 (Thu, 22 Feb 2018)" );
	script_tag( name: "cvss_base", value: "5.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:N" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-03-03 17:15:00 +0000 (Tue, 03 Mar 2020)" );
	script_cve_id( "CVE-2018-19796" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_name( "WordPress Ninja Forms Plugin < 3.3.19.1 Open Redirect Vulnerability" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "gb_wordpress_plugin_http_detect.sc" );
	script_mandatory_keys( "wordpress/plugin/ninja-forms/detected" );
	script_tag( name: "summary", value: "An open redirect vulnerability in Ninja Forms plugin for WordPress allows
  remote attackers to redirect a user via the lib/StepProcessing/step-processing.php (aka submissions download page) redirect parameter." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "affected", value: "WordPress Ninja Forms plugin before version 3.3.19.1." );
	script_tag( name: "solution", value: "Update to version 3.3.19.1 or later." );
	script_xref( name: "URL", value: "https://wordpress.org/plugins/ninja-forms/#developers" );
	exit( 0 );
}
CPE = "cpe:/a:thewpninjas:ninja-forms";
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
if(version_is_less( version: version, test_version: "3.3.19.1" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "3.3.19.1", install_path: location );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

