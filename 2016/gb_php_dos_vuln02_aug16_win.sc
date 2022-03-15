CPE = "cpe:/a:php:php";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.809138" );
	script_version( "2021-09-20T10:01:48+0000" );
	script_cve_id( "CVE-2016-5114" );
	script_bugtraq_id( 81808 );
	script_tag( name: "cvss_base", value: "6.4" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:N/A:P" );
	script_tag( name: "last_modification", value: "2021-09-20 10:01:48 +0000 (Mon, 20 Sep 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2018-01-05 02:30:00 +0000 (Fri, 05 Jan 2018)" );
	script_tag( name: "creation_date", value: "2016-08-17 15:48:17 +0530 (Wed, 17 Aug 2016)" );
	script_name( "PHP Denial of Service Vulnerability - 02 - Aug16 (Windows)" );
	script_tag( name: "summary", value: "PHP is prone to a denial of service (DoS) vulnerability." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "The flaw is due to the 'sapi/fpm/fpm/fpm_log.c'
  script misinterprets the semantics of the snprintf return value." );
	script_tag( name: "impact", value: "Successfully exploiting this issue allow
  attackers to obtain sensitive information from process memory or cause a
  denial of service (out-of-bounds read and buffer overflow) via a long string." );
	script_tag( name: "affected", value: "PHP versions before 5.5.31, 5.6.x before
  5.6.17, and 7.x before 7.0.2 on Windows." );
	script_tag( name: "solution", value: "Update to PHP version 5.5.31, or 5.6.17,
  or 7.0.2, or later." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_xref( name: "URL", value: "http://www.php.net/ChangeLog-5.php" );
	script_copyright( "Copyright (C) 2016 Greenbone Networks GmbH" );
	script_category( ACT_GATHER_INFO );
	script_family( "Denial of Service" );
	script_dependencies( "secpod_php_smb_login_detect.sc", "gb_php_http_detect.sc", "os_detection.sc" );
	script_mandatory_keys( "php/detected", "Host/runs_windows" );
	exit( 0 );
}
require("version_func.inc.sc");
require("host_details.inc.sc");
if(isnull( phpPort = get_app_port( cpe: CPE ) )){
	exit( 0 );
}
if(!phpVer = get_app_version( cpe: CPE, port: phpPort )){
	exit( 0 );
}
if( version_is_less( version: phpVer, test_version: "5.5.31" ) ){
	fix = "5.5.31";
	VULN = TRUE;
}
else {
	if( IsMatchRegexp( phpVer, "^5\\.6" ) ){
		if(version_in_range( version: phpVer, test_version: "5.6.0", test_version2: "5.6.16" )){
			fix = "5.6.17";
			VULN = TRUE;
		}
	}
	else {
		if(IsMatchRegexp( phpVer, "^7\\.0" )){
			if(version_in_range( version: phpVer, test_version: "7.0", test_version2: "7.0.1" )){
				fix = "7.0.2";
				VULN = TRUE;
			}
		}
	}
}
if(VULN){
	report = report_fixed_ver( installed_version: phpVer, fixed_version: fix );
	security_message( data: report, port: phpPort );
	exit( 0 );
}
exit( 99 );

