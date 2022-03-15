CPE = "cpe:/a:drupal:drupal";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.812583" );
	script_version( "2021-09-29T12:07:39+0000" );
	script_cve_id( "CVE-2018-7600" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2021-09-29 12:07:39 +0000 (Wed, 29 Sep 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-03-01 18:04:00 +0000 (Fri, 01 Mar 2019)" );
	script_tag( name: "creation_date", value: "2018-03-29 09:55:26 +0530 (Thu, 29 Mar 2018)" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_name( "Drupal Core Critical Remote Code Execution Vulnerability (SA-CORE-2018-002) - Windows, Version Check" );
	script_tag( name: "summary", value: "Drupal is prone to a critical remote code execution (RCE)
  vulnerability." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "The flaw exists within multiple subsystems
  of Drupal. This potentially allows attackers to exploit multiple attack
  vectors on a Drupal site, which could result in the site being completely
  compromised." );
	script_tag( name: "impact", value: "Successful exploitation will allow remote
  attackers to execute arbitrary code and completely compromise the site." );
	script_tag( name: "affected", value: "Drupal core versions 6.x and earlier,

  Drupal core versions 8.2.x and earlier,

  Drupal core versions 8.3.x to before 8.3.9,

  Drupal core versions 8.4.x to before 8.4.6,

  Drupal core versions 8.5.x to before 8.5.1 and

  Drupal core versions 7.x to before 7.58." );
	script_tag( name: "solution", value: "Update to version 8.3.9 or
  8.4.6 or 8.5.1 or 7.58 or later. Please see the referenced links for available updates." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "URL", value: "https://www.drupal.org/psa-2018-001" );
	script_xref( name: "URL", value: "https://www.drupal.org/sa-core-2018-002" );
	script_xref( name: "URL", value: "https://www.drupal.org/project/drupal/releases/7.58" );
	script_xref( name: "URL", value: "https://www.drupal.org/project/drupal/releases/8.3.9" );
	script_xref( name: "URL", value: "https://www.drupal.org/project/drupal/releases/8.4.6" );
	script_xref( name: "URL", value: "https://www.drupal.org/project/drupal/releases/8.5.1" );
	script_xref( name: "URL", value: "https://research.checkpoint.com/uncovering-drupalgeddon-2/" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "drupal_detect.sc", "os_detection.sc" );
	script_mandatory_keys( "drupal/installed", "Host/runs_windows" );
	exit( 0 );
}
require("host_details.inc.sc");
require("version_func.inc.sc");
if(!port = get_app_port( cpe: CPE )){
	exit( 0 );
}
if(!infos = get_app_version_and_location( cpe: CPE, port: port, version_regex: "^([0-9]+)", exit_no_version: TRUE )){
	exit( 0 );
}
vers = infos["version"];
path = infos["location"];
if(IsMatchRegexp( vers, "^6\\." )){
	fix = "Drupal 6 is End of Life. Please contact a D6LTS vendor.";
}
if(IsMatchRegexp( vers, "^8\\.2" ) || vers == "8.5.0"){
	fix = "8.5.1";
}
if(IsMatchRegexp( vers, "^8\\.3" ) && version_in_range( version: vers, test_version: "8.3.0", test_version2: "8.3.8" )){
	fix = "8.3.9";
}
if(IsMatchRegexp( vers, "^8\\.4" ) && version_in_range( version: vers, test_version: "8.4.0", test_version2: "8.4.5" )){
	fix = "8.4.6";
}
if(IsMatchRegexp( vers, "^7\\." ) && version_in_range( version: vers, test_version: "7.0", test_version2: "7.57" )){
	fix = "7.58";
}
if(fix){
	report = report_fixed_ver( installed_version: vers, fixed_version: fix, install_path: path );
	security_message( data: report, port: port );
	exit( 0 );
}
exit( 99 );

