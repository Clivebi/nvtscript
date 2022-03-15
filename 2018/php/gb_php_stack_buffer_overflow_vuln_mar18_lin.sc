CPE = "cpe:/a:php:php";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.812821" );
	script_version( "2021-06-02T11:05:57+0000" );
	script_cve_id( "CVE-2018-7584" );
	script_bugtraq_id( 103204 );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2021-06-02 11:05:57 +0000 (Wed, 02 Jun 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-08-19 11:15:00 +0000 (Mon, 19 Aug 2019)" );
	script_tag( name: "creation_date", value: "2018-03-12 17:24:20 +0530 (Mon, 12 Mar 2018)" );
	script_name( "PHP Stack Buffer Overflow Vulnerability Mar18 (Linux)" );
	script_tag( name: "summary", value: "PHP is prone to a stack buffer overflow vulnerability." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "The flaw exists because php fails to
  adequately bounds-check user-supplied data before copying it into an
  insufficiently sized buffer." );
	script_tag( name: "impact", value: "Successful exploitation will allow an attacker
  to execute arbitrary code in the context of the affected application. Failed
  exploit attempts will result in denial-of-service conditions." );
	script_tag( name: "affected", value: "PHP versions 7.2.x prior to 7.2.3,

  PHP versions 7.0.x prior to 7.0.28,

  PHP versions 5.0.x prior to 5.6.34 and

  PHP versions 7.1.x prior to 7.1.15 on Linux." );
	script_tag( name: "solution", value: "Update to version 7.2.3, 7.0.28,
  5.6.34, 7.1.15 or later." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "remote_banner_unreliable" );
	script_xref( name: "URL", value: "http://php.net/ChangeLog-7.php" );
	script_xref( name: "URL", value: "https://bugs.php.net/bug.php?id=75981" );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH" );
	script_category( ACT_GATHER_INFO );
	script_family( "Web application abuses" );
	script_dependencies( "gb_php_ssh_login_detect.sc", "gb_php_http_detect.sc", "os_detection.sc" );
	script_mandatory_keys( "php/detected", "Host/runs_unixoide" );
	exit( 0 );
}
require("version_func.inc.sc");
require("host_details.inc.sc");
if(isnull( port = get_app_port( cpe: CPE ) )){
	exit( 0 );
}
if(!infos = get_app_version_and_location( cpe: CPE, port: port, exit_no_version: TRUE )){
	exit( 0 );
}
vers = infos["version"];
path = infos["location"];
if( version_in_range( version: vers, test_version: "7.2", test_version2: "7.2.2" ) ){
	fix = "7.2.3";
}
else {
	if( version_in_range( version: vers, test_version: "7.0", test_version2: "7.0.27" ) ){
		fix = "7.0.28";
	}
	else {
		if( version_in_range( version: vers, test_version: "7.1", test_version2: "7.1.14" ) ){
			fix = "7.1.15";
		}
		else {
			if(version_in_range( version: vers, test_version: "5.0", test_version2: "5.6.33" )){
				fix = "5.6.34";
			}
		}
	}
}
if(fix){
	report = report_fixed_ver( installed_version: vers, fixed_version: fix, install_path: path );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

