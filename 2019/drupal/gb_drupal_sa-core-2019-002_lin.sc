CPE = "cpe:/a:drupal:drupal";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.141891" );
	script_version( "2021-08-30T09:01:25+0000" );
	script_tag( name: "last_modification", value: "2021-08-30 09:01:25 +0000 (Mon, 30 Aug 2021)" );
	script_tag( name: "creation_date", value: "2019-01-18 10:26:41 +0700 (Fri, 18 Jan 2019)" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-10-09 23:51:00 +0000 (Wed, 09 Oct 2019)" );
	script_cve_id( "CVE-2018-1000888", "CVE-2019-6339", "CVE-2019-6338" );
	script_tag( name: "qod_type", value: "remote_banner_unreliable" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_name( "Drupal Multiple Vulnerabilities (SA-CORE-2019-001/SA-CORE-2019-002) (Linux)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2019 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "drupal_detect.sc", "os_detection.sc" );
	script_mandatory_keys( "drupal/installed", "Host/runs_unixoide" );
	script_tag( name: "summary", value: "Drupal is prone to multiple vulnerabilities." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "Drupal is prone to multiple vulnerabilities:

  - Drupal core uses the third-party PEAR Archive_Tar library. This library has released a security update which
    impacts some Drupal configurations. (CVE-2018-1000888)

  - A remote code execution vulnerability exists in PHP's built-in phar stream wrapper when performing file
    operations on an untrusted phar:// URI." );
	script_tag( name: "affected", value: "Drupal 7.x, 8.5.x and 8.6.x." );
	script_tag( name: "solution", value: "Update to version 7.62, 8.5.9, 8.6.6 or later." );
	script_xref( name: "URL", value: "https://www.drupal.org/sa-core-2019-001" );
	script_xref( name: "URL", value: "https://www.drupal.org/sa-core-2019-002" );
	exit( 0 );
}
require("host_details.inc.sc");
require("version_func.inc.sc");
if(!port = get_app_port( cpe: CPE )){
	exit( 0 );
}
if(!version = get_app_version( cpe: CPE, port: port )){
	exit( 0 );
}
if(version_in_range( version: version, test_version: "7.0", test_version2: "7.61" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "7.62" );
	security_message( port: port, data: report );
	exit( 0 );
}
if(version_in_range( version: version, test_version: "8.5", test_version2: "8.5.8" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "8.5.9" );
	security_message( port: port, data: report );
	exit( 0 );
}
if(version_in_range( version: version, test_version: "8.6", test_version2: "8.6.5" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "8.6.6" );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

