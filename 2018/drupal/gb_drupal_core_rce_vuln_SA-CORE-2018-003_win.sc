CPE = "cpe:/a:drupal:drupal";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.813211" );
	script_version( "2021-09-29T12:07:39+0000" );
	script_cve_id( "CVE-2018-9861" );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:P/A:N" );
	script_tag( name: "last_modification", value: "2021-09-29 12:07:39 +0000 (Wed, 29 Sep 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-07-18 13:15:00 +0000 (Thu, 18 Jul 2019)" );
	script_tag( name: "creation_date", value: "2018-04-19 14:09:14 +0530 (Thu, 19 Apr 2018)" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_name( "Drupal Cross Site Scripting Vulnerability (SA-CORE-2018-003) - Windows" );
	script_tag( name: "summary", value: "Drupal is prone to a cross-site scripting (XSS) vulnerability." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "The flaw exists in 'CKEditor' used within
  the 'Enhanced Image (image2)' plugin, Which allows attackers to execute XSS
  inside CKEditor using the '<img>' tag and specially crafted HTML." );
	script_tag( name: "impact", value: "Successful exploitation will allow remote
  attackers to execute a script on victim's Web browser within the security
  context of the hosting Web site." );
	script_tag( name: "affected", value: "Drupal core versions 8.x before 8.4.7 and

  Drupal core versions 8.5.0 before 8.5.2." );
	script_tag( name: "solution", value: "Update to version 8.4.7,
  8.5.2 or later. Please see the references for more information." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "URL", value: "https://www.drupal.org/sa-core-2018-003" );
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
if(!infos = get_app_version_and_location( cpe: CPE, port: port, version_regex: "^[0-9]\\.[0-9.]+", exit_no_version: TRUE )){
	exit( 0 );
}
vers = infos["version"];
path = infos["location"];
if(version_in_range( version: vers, test_version: "8.4.0", test_version2: "8.4.6" )){
	report = report_fixed_ver( installed_version: vers, fixed_version: "8.4.7", install_path: path );
	security_message( data: report, port: port );
	exit( 0 );
}
if(version_in_range( version: vers, test_version: "8.5.0", test_version2: "8.5.1" )){
	report = report_fixed_ver( installed_version: vers, fixed_version: "8.5.2", install_path: path );
	security_message( data: report, port: port );
	exit( 0 );
}
exit( 99 );

