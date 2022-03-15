CPE = "cpe:/a:drupal:drupal";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.146347" );
	script_version( "2021-08-17T09:01:01+0000" );
	script_tag( name: "last_modification", value: "2021-08-17 09:01:01 +0000 (Tue, 17 Aug 2021)" );
	script_tag( name: "creation_date", value: "2021-07-22 05:26:56 +0000 (Thu, 22 Jul 2021)" );
	script_tag( name: "cvss_base", value: "3.6" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:L/Au:N/C:P/I:P/A:N" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-08-06 20:47:00 +0000 (Fri, 06 Aug 2021)" );
	script_cve_id( "CVE-2021-32610" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_name( "Drupal 7.x < 7.82, 8.0.x < 8.9.17, 9.x < 9.1.11, 9.2.x < 9.2.2 Archive_Tar library Vulnerability (SA-CORE-2021-004) - Windows" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "drupal_detect.sc", "os_detection.sc" );
	script_mandatory_keys( "drupal/installed", "Host/runs_windows" );
	script_tag( name: "summary", value: "Drupal is prone to a vulnerability in the third-party library
  Archive_Tar." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "The Drupal project uses the pear Archive_Tar library, which has
  released a security update that impacts Drupal.

  The vulnerability is mitigated by the fact that Drupal core's use of the Archive_Tar library is
  not vulnerable, as it does not permit symlinks.

  Exploitation may be possible if contrib or custom code uses the library to extract tar archives
  (for example .tar, .tar.gz, .bz2, or .tlz) which come from a potentially untrusted source." );
	script_tag( name: "affected", value: "Drupal version 7.x through 7.81, 8.0.x through 8.9.16, 9.x
  through 9.1.10 and 9.2.x through 9.2.1." );
	script_tag( name: "solution", value: "Update to version 7.82, 8.9.17, 9.1.11, 9.2.2 or later." );
	script_xref( name: "URL", value: "https://www.drupal.org/sa-core-2021-004" );
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
if(version_in_range( version: version, test_version: "7.0", test_version2: "7.81" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "7.82", install_path: location );
	security_message( port: port, data: report );
	exit( 0 );
}
if(version_in_range( version: version, test_version: "8.0", test_version2: "8.9.16" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "8.9.17", install_path: location );
	security_message( port: port, data: report );
	exit( 0 );
}
if(version_in_range( version: version, test_version: "9.0", test_version2: "9.1.10" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "9.1.11", install_path: location );
	security_message( port: port, data: report );
	exit( 0 );
}
if(version_in_range( version: version, test_version: "9.2", test_version2: "9.2.1" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "9.2.2", install_path: location );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

