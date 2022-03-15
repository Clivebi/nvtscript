CPE = "cpe:/a:php:php";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.811483" );
	script_version( "2021-09-14T14:01:45+0000" );
	script_cve_id( "CVE-2017-11147" );
	script_tag( name: "cvss_base", value: "6.4" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:N/A:P" );
	script_tag( name: "last_modification", value: "2021-09-14 14:01:45 +0000 (Tue, 14 Sep 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-10-03 00:03:00 +0000 (Thu, 03 Oct 2019)" );
	script_tag( name: "creation_date", value: "2017-07-11 19:48:21 +0530 (Tue, 11 Jul 2017)" );
	script_name( "PHP 'phar_parse_pharfile' Function Denial of Service Vulnerability - (Windows)" );
	script_tag( name: "summary", value: "PHP is prone to a denial of service (DoS) vulnerability." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "The flaw exists due to a buffer over-read error
  in the 'phar_parse_pharfile' function in ext/phar/phar.c script." );
	script_tag( name: "impact", value: "Successfully exploiting this issue allow
  remote attackers to supply malicious archive files to crash the PHP interpreter or
  potentially disclose information." );
	script_tag( name: "affected", value: "PHP versions before 5.6.30, 7.x before 7.0.15" );
	script_tag( name: "solution", value: "Update to PHP version 5.6.30 or 7.0.15,
  or later." );
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
if(version_is_less( version: vers, test_version: "5.6.30" )){
	fix = "5.6.30";
}
if(version_in_range( version: vers, test_version: "7.0", test_version2: "7.0.14" )){
	fix = "7.0.15";
}
if(fix){
	report = report_fixed_ver( installed_version: vers, fixed_version: fix );
	security_message( port: phpport, data: report );
	exit( 0 );
}
exit( 99 );

