CPE = "cpe:/a:drupal:drupal";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.141029" );
	script_version( "2021-05-27T09:28:58+0000" );
	script_tag( name: "last_modification", value: "2021-05-27 09:28:58 +0000 (Thu, 27 May 2021)" );
	script_tag( name: "creation_date", value: "2018-04-26 08:47:32 +0700 (Thu, 26 Apr 2018)" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-04-20 12:52:00 +0000 (Tue, 20 Apr 2021)" );
	script_cve_id( "CVE-2018-7602" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_name( "Drupal Core Critical Remote Code Execution Vulnerability (SA-CORE-2018-004) (Windows, Version Check)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "drupal_detect.sc", "os_detection.sc" );
	script_mandatory_keys( "drupal/installed", "Host/runs_windows" );
	script_tag( name: "summary", value: "Drupal is prone to a remote code execution vulnerability." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "A remote code execution vulnerability exists within multiple subsystems of
  Drupal 7.x and 8.x. This potentially allows attackers to exploit multiple attack vectors on a Drupal site, which
  could result in the site being compromised. This vulnerability is related to SA-CORE-2018-002 (CVE-2018-7600)." );
	script_tag( name: "affected", value: "Drupal 7.x and 8.x" );
	script_tag( name: "solution", value: "Update to version 7.59, 8.4.8, 8.5.3 or later." );
	script_xref( name: "URL", value: "https://www.drupal.org/sa-core-2018-004" );
	exit( 0 );
}
require("host_details.inc.sc");
require("version_func.inc.sc");
if(!port = get_app_port( cpe: CPE )){
	exit( 0 );
}
if(!infos = get_app_version_and_location( cpe: CPE, port: port, version_regex: "^[0-9]\\.[0-9.]+", exit_no_version: TRUE )){
	exit( 0 );
}
version = infos["version"];
path = infos["location"];
if(version_in_range( version: version, test_version: "7.0", test_version2: "7.58" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "7.59", install_path: path );
	security_message( port: port, data: report );
	exit( 0 );
}
if(version_in_range( version: version, test_version: "8.0", test_version2: "8.4.7" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "8.4.8", install_path: path );
	security_message( port: port, data: report );
	exit( 0 );
}
if(version_in_range( version: version, test_version: "8.5", test_version2: "8.5.2" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "8.5.3", install_path: path );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

