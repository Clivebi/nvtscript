CPE = "cpe:/a:drupal:drupal";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.145810" );
	script_version( "2021-04-22T06:54:20+0000" );
	script_tag( name: "last_modification", value: "2021-04-22 06:54:20 +0000 (Thu, 22 Apr 2021)" );
	script_tag( name: "creation_date", value: "2021-04-22 06:47:14 +0000 (Thu, 22 Apr 2021)" );
	script_tag( name: "cvss_base", value: "6.4" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:N" );
	script_tag( name: "qod_type", value: "remote_banner_unreliable" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_name( "Drupal 7.x, 8.x, 9.x XSS Vulnerability (SA-CORE-2021-002) - Linux" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "drupal_detect.sc", "os_detection.sc" );
	script_mandatory_keys( "drupal/installed", "Host/runs_unixoide" );
	script_tag( name: "summary", value: "Drupal is prone to a cross-site scripting (XSS) vulnerability." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "Drupal core's sanitization API fails to properly filter XSS
  under certain circumstances.

  Note: Not all sites and users are affected, but configuration changes to prevent the exploit
  might be impractical and will vary between sites." );
	script_tag( name: "affected", value: "Drupal 7.x, 8.x, 9.0.x and 9.1.x." );
	script_tag( name: "solution", value: "Update to version 7.80, 8.9.14, 9.0.12, 9.1.7 or later." );
	script_xref( name: "URL", value: "https://www.drupal.org/sa-core-2021-002" );
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
if(version_is_less( version: version, test_version: "7.80" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "7.80", install_path: location );
	security_message( port: port, data: report );
	exit( 0 );
}
if(version_in_range( version: version, test_version: "8.0", test_version2: "8.9.13" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "8.9.14", install_path: location );
	security_message( port: port, data: report );
	exit( 0 );
}
if(version_in_range( version: version, test_version: "9.0", test_version2: "9.0.11" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "9.0.12", install_path: location );
	security_message( port: port, data: report );
	exit( 0 );
}
if(version_in_range( version: version, test_version: "9.1", test_version2: "9.1.6" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "9.1.7", install_path: location );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

