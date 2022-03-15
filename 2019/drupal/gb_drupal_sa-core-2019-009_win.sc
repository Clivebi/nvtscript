CPE = "cpe:/a:drupal:drupal";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.143281" );
	script_version( "2019-12-19T13:07:43+0000" );
	script_tag( name: "last_modification", value: "2019-12-19 13:07:43 +0000 (Thu, 19 Dec 2019)" );
	script_tag( name: "creation_date", value: "2019-12-19 12:57:16 +0000 (Thu, 19 Dec 2019)" );
	script_tag( name: "cvss_base", value: "7.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:C" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_name( "Drupal 8.x Multiple Vulnerabilities (SA-CORE-2019-009, SA-CORE-2019-010, SA-CORE-2019-011) (Windows)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2019 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "drupal_detect.sc", "os_detection.sc" );
	script_mandatory_keys( "drupal/installed", "Host/runs_windows" );
	script_tag( name: "summary", value: "Drupal is prone to multiple vulnerabilities." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "Drupal is prone to multiple vulnerabilities:

  - DoS vulnerability in install.php

  - Vulnerability in file_save_upload() function

  - Access bypass vulnerability" );
	script_tag( name: "affected", value: "Drupal 8.7.x and earlier and 8.8.x." );
	script_tag( name: "solution", value: "Update to version 8.7.11, 8.8.1 or later." );
	script_xref( name: "URL", value: "https://www.drupal.org/sa-core-2019-009" );
	script_xref( name: "URL", value: "https://www.drupal.org/sa-core-2019-010" );
	script_xref( name: "URL", value: "https://www.drupal.org/sa-core-2019-011" );
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
if(version_in_range( version: version, test_version: "8.0", test_version2: "8.7.10" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "8.7.11", install_path: location );
	security_message( port: port, data: report );
	exit( 0 );
}
if(version_is_equal( version: version, test_version: "8.8.0" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "8.8.1", install_path: location );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

