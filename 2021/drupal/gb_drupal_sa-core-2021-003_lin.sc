CPE = "cpe:/a:drupal:drupal";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.112890" );
	script_version( "2021-05-27T09:56:08+0000" );
	script_tag( name: "last_modification", value: "2021-05-27 09:56:08 +0000 (Thu, 27 May 2021)" );
	script_tag( name: "creation_date", value: "2021-05-27 09:49:11 +0000 (Thu, 27 May 2021)" );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:P/A:N" );
	script_tag( name: "qod_type", value: "remote_banner_unreliable" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_name( "Drupal < 8.9.16, 9.0.x < 9.0.14, 9.1.x < 9.1.9 XSS Vulnerability (SA-CORE-2021-003) - Linux" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "drupal_detect.sc", "os_detection.sc" );
	script_mandatory_keys( "drupal/installed", "Host/runs_unixoide" );
	script_tag( name: "summary", value: "Drupal is prone to a cross-site scripting (XSS) vulnerability." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "Drupal core uses the third-party CKEditor library. This library
  has an error in parsing HTML that could lead to an XSS attack.

  This issue is mitigated by the fact that it only affects sites with CKEditor enabled." );
	script_tag( name: "affected", value: "Drupal before 8.9.16, 9.0.x before 9.0.14,
  and 9.1.x before 9.1.9." );
	script_tag( name: "solution", value: "Update to version 8.9.16, 9.0.14, 9.1.9 or later." );
	script_xref( name: "URL", value: "https://www.drupal.org/sa-core-2021-003" );
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
if(version_is_less( version: version, test_version: "8.9.16" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "8.9.16", install_path: location );
	security_message( port: port, data: report );
	exit( 0 );
}
if(version_in_range( version: version, test_version: "9.0", test_version2: "9.0.13" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "9.0.14", install_path: location );
	security_message( port: port, data: report );
	exit( 0 );
}
if(version_in_range( version: version, test_version: "9.1", test_version2: "9.1.8" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "9.1.9", install_path: location );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

