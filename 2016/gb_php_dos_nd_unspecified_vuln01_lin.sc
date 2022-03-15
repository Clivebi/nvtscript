CPE = "cpe:/a:php:php";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.808607" );
	script_version( "2021-09-20T13:02:01+0000" );
	script_cve_id( "CVE-2016-4342", "CVE-2016-2554" );
	script_bugtraq_id( 89154, 83353 );
	script_tag( name: "cvss_base", value: "10.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:C/A:C" );
	script_tag( name: "last_modification", value: "2021-09-20 13:02:01 +0000 (Mon, 20 Sep 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2018-01-05 02:30:00 +0000 (Fri, 05 Jan 2018)" );
	script_tag( name: "creation_date", value: "2016-07-14 12:14:00 +0530 (Thu, 14 Jul 2016)" );
	script_name( "PHP Denial of Service And Unspecified Vulnerabilities - 01 - Jul16 (Linux)" );
	script_tag( name: "summary", value: "PHP is prone to denial of service and unspecified vulnerabilities." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "The flaw is due an improper handling of zero-length
  uncompressed data in 'ext/phar/phar_object.c' script." );
	script_tag( name: "impact", value: "Successfully exploiting this issue allow
  remote attackers to cause a denial of service (heap memory corruption) or
  possibly have unspecified other impact." );
	script_tag( name: "affected", value: "PHP versions prior to 5.5.32, 5.6.x
  before 5.6.18, and 7.x before 7.0.3 on Linux" );
	script_tag( name: "solution", value: "Update to PHP version 5.5.32,
  or 5.6.18, or 7.0.3, or later." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "remote_banner_unreliable" );
	script_xref( name: "URL", value: "http://www.php.net/ChangeLog-7.php" );
	script_xref( name: "URL", value: "http://www.openwall.com/lists/oss-security/2016/04/28/2" );
	script_copyright( "Copyright (C) 2016 Greenbone Networks GmbH" );
	script_category( ACT_GATHER_INFO );
	script_family( "Web application abuses" );
	script_dependencies( "gb_php_ssh_login_detect.sc", "gb_php_http_detect.sc", "os_detection.sc" );
	script_mandatory_keys( "php/detected", "Host/runs_unixoide" );
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
if( version_is_less( version: phpVer, test_version: "5.5.32" ) ){
	fix = "5.5.32";
	VULN = TRUE;
}
else {
	if( IsMatchRegexp( phpVer, "^5\\.6" ) ){
		if(version_in_range( version: phpVer, test_version: "5.6.0", test_version2: "5.6.17" )){
			fix = "5.6.18";
			VULN = TRUE;
		}
	}
	else {
		if(IsMatchRegexp( phpVer, "^7\\.0" )){
			if(version_in_range( version: phpVer, test_version: "7.0", test_version2: "7.0.2" )){
				fix = "7.0.3";
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

