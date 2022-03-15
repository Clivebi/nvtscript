CPE = "cpe:/a:drupal:drupal";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.145252" );
	script_version( "2021-08-17T09:01:01+0000" );
	script_tag( name: "last_modification", value: "2021-08-17 09:01:01 +0000 (Tue, 17 Aug 2021)" );
	script_tag( name: "creation_date", value: "2021-01-25 06:01:27 +0000 (Mon, 25 Jan 2021)" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:P/A:N" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-04-23 12:52:00 +0000 (Fri, 23 Apr 2021)" );
	script_cve_id( "CVE-2020-36193" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_name( "Drupal 7.x, 8.x, 9.x Archive_Tar library Vulnerability (SA-CORE-2021-001) - Windows" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "drupal_detect.sc", "os_detection.sc" );
	script_mandatory_keys( "drupal/installed", "Host/runs_windows" );
	script_tag( name: "summary", value: "Drupal is prone to a vulnerability in the Archive_Tar
  library." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "The Drupal project uses the pear Archive_Tar library,
  which has released a security update that impacts Drupal.

  Exploits may be possible if Drupal is configured to allow .tar, .tar.gz, .bz2, or .tlz
  file uploads and processes them." );
	script_tag( name: "affected", value: "Drupal 7.x, 8.9.x and prior, 9.0.x and 9.1.x." );
	script_tag( name: "solution", value: "Update to version 7.78, 8.9.13, 9.0.11, 9.1.3 or later.
  Disable uploads of .tar, .tar.gz, .bz2, or .tlz files to mitigate the vulnerability." );
	script_xref( name: "URL", value: "https://www.drupal.org/sa-core-2021-001" );
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
if(version_is_less( version: version, test_version: "7.78" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "7.78", install_path: location );
	security_message( port: port, data: report );
	exit( 0 );
}
if(version_in_range( version: version, test_version: "8.0", test_version2: "8.9.12" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "8.9.13", install_path: location );
	security_message( port: port, data: report );
	exit( 0 );
}
if(version_in_range( version: version, test_version: "9.0", test_version2: "9.0.10" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "9.0.11", install_path: location );
	security_message( port: port, data: report );
	exit( 0 );
}
if(version_in_range( version: version, test_version: "9.1", test_version2: "9.1.2" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "9.1.3", install_path: location );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

