CPE = "cpe:/a:drupal:drupal";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.144925" );
	script_version( "2021-07-06T11:00:47+0000" );
	script_tag( name: "last_modification", value: "2021-07-06 11:00:47 +0000 (Tue, 06 Jul 2021)" );
	script_tag( name: "creation_date", value: "2020-11-30 05:26:16 +0000 (Mon, 30 Nov 2020)" );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-02-02 14:36:00 +0000 (Tue, 02 Feb 2021)" );
	script_cve_id( "CVE-2020-28948", "CVE-2020-28949" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_name( "Drupal 7.x, 8.x, 9.x RCE Vulnerability (SA-CORE-2020-013) (Windows)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "drupal_detect.sc", "os_detection.sc" );
	script_mandatory_keys( "drupal/installed", "Host/runs_windows" );
	script_tag( name: "summary", value: "Drupal is prone to a remote code execution (RCE) vulnerability." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "The Drupal project uses the PEAR Archive_Tar library. The PEAR Archive_Tar
  library has released a security update that impacts Drupal. Multiple vulnerabilities are possible if Drupal is
  configured to allow .tar, .tar.gz, .bz2, or .tlz file uploads and processes them." );
	script_tag( name: "affected", value: "Drupal 7.x, 8.8.x and prior, 8.9.x and 9.0.x." );
	script_tag( name: "solution", value: "Update to version 7.75, 8.8.12, 8.9.10, 9.0.9 or later. To mitigate this
  issue, prevent untrusted users from uploading .tar, .tar.gz, .bz2, or .tlz files." );
	script_xref( name: "URL", value: "https://www.drupal.org/sa-core-2020-013" );
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
if(version_is_less( version: version, test_version: "7.75" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "7.75", install_path: location );
	security_message( port: port, data: report );
	exit( 0 );
}
if(version_in_range( version: version, test_version: "8.0", test_version2: "8.8.11" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "8.8.12", install_path: location );
	security_message( port: port, data: report );
	exit( 0 );
}
if(version_in_range( version: version, test_version: "8.9", test_version2: "8.9.9" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "8.9.10", install_path: location );
	security_message( port: port, data: report );
	exit( 0 );
}
if(version_in_range( version: version, test_version: "9.0", test_version2: "9.0.8" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "9.0.9", install_path: location );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

