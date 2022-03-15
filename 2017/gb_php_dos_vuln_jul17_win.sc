CPE = "cpe:/a:php:php";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.811486" );
	script_version( "2021-09-10T08:01:37+0000" );
	script_cve_id( "CVE-2017-11142" );
	script_tag( name: "cvss_base", value: "7.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:C" );
	script_tag( name: "last_modification", value: "2021-09-10 08:01:37 +0000 (Fri, 10 Sep 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2018-01-14 02:29:00 +0000 (Sun, 14 Jan 2018)" );
	script_tag( name: "creation_date", value: "2017-07-13 17:38:21 +0530 (Thu, 13 Jul 2017)" );
	script_name( "PHP Denial of Service Vulnerability Jul17 (Windows)" );
	script_tag( name: "summary", value: "PHP is prone to a denial of service (DoS) vulnerability." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "The flaw exists due to improper handling of long
  form variables in main/php_variables.c script." );
	script_tag( name: "impact", value: "Successfully exploiting this issue allow
  an attacker to cause a CPU consumption denial of service attack." );
	script_tag( name: "affected", value: "PHP versions before 5.6.31, 7.x before 7.0.17,
  and 7.1.x before 7.1.3" );
	script_tag( name: "solution", value: "Update to PHP version 5.6.31, 7.0.17,
  7.1.3 or later." );
	script_xref( name: "URL", value: "http://www.php.net/ChangeLog-5.php" );
	script_xref( name: "URL", value: "http://www.php.net/ChangeLog-7.php" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_copyright( "Copyright (C) 2017 Greenbone Networks GmbH" );
	script_category( ACT_GATHER_INFO );
	script_family( "Denial of Service" );
	script_dependencies( "secpod_php_smb_login_detect.sc", "gb_php_http_detect.sc", "os_detection.sc" );
	script_mandatory_keys( "php/detected", "Host/runs_windows" );
	exit( 0 );
}
require("version_func.inc.sc");
require("host_details.inc.sc");
if(isnull( phpport = get_app_port( cpe: CPE ) )){
	exit( 0 );
}
if(!vers = get_app_version( cpe: CPE, port: phpport )){
	exit( 0 );
}
if( version_is_less( version: vers, test_version: "5.6.31" ) ){
	fix = "5.6.31";
}
else {
	if( version_in_range( version: vers, test_version: "7.0", test_version2: "7.0.16" ) ){
		fix = "7.0.17";
	}
	else {
		if(version_in_range( version: vers, test_version: "7.1", test_version2: "7.1.2" )){
			fix = "7.1.3";
		}
	}
}
if(fix){
	report = report_fixed_ver( installed_version: vers, fixed_version: fix );
	security_message( port: phpport, data: report );
	exit( 0 );
}
exit( 99 );

