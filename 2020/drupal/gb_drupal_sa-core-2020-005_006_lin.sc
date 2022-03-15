CPE = "cpe:/a:drupal:drupal";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.144148" );
	script_version( "2021-07-06T11:00:47+0000" );
	script_tag( name: "last_modification", value: "2021-07-06 11:00:47 +0000 (Tue, 06 Jul 2021)" );
	script_tag( name: "creation_date", value: "2020-06-19 06:59:12 +0000 (Fri, 19 Jun 2020)" );
	script_tag( name: "cvss_base", value: "9.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:C/I:C/A:C" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-05-14 18:10:00 +0000 (Fri, 14 May 2021)" );
	script_cve_id( "CVE-2020-13664", "CVE-2020-13665" );
	script_tag( name: "qod_type", value: "remote_banner_unreliable" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_name( "Drupal 8.x, 9.x Multiple Vulnerabilities (SA-CORE-2020-005, SA-CORE-2020-006) (Linux)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "drupal_detect.sc", "os_detection.sc" );
	script_mandatory_keys( "drupal/installed", "Host/runs_unixoide" );
	script_tag( name: "summary", value: "Drupal is prone to multiple vulnerabilities." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "Drupal is prone to multiple vulnerabilities:

  - Arbitrary PHP code execution (CVE-2020-13664)

  - Access bypass (CVE-2020-13665)" );
	script_tag( name: "affected", value: "Drupal 8.8.x and earlier, 8.9.x and 9.0.x." );
	script_tag( name: "solution", value: "Update to version 8.8.8, 8.9.1, 9.0.1 or later." );
	script_xref( name: "URL", value: "https://www.drupal.org/sa-core-2020-005" );
	script_xref( name: "URL", value: "https://www.drupal.org/sa-core-2020-006" );
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
if(version_in_range( version: version, test_version: "8.0", test_version2: "8.8.7" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "8.8.8", install_path: location );
	security_message( port: port, data: report );
	exit( 0 );
}
if(version == "8.9.0"){
	report = report_fixed_ver( installed_version: version, fixed_version: "8.9.1", install_path: location );
	security_message( port: port, data: report );
	exit( 0 );
}
if(version == "9.0.0"){
	report = report_fixed_ver( installed_version: version, fixed_version: "9.0.1", install_path: location );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

