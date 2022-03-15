CPE = "cpe:/a:php:php";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.808613" );
	script_version( "2021-04-13T14:13:08+0000" );
	script_cve_id( "CVE-2015-8878" );
	script_bugtraq_id( 90837 );
	script_tag( name: "cvss_base", value: "7.1" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:N/A:C" );
	script_tag( name: "last_modification", value: "2021-04-13 14:13:08 +0000 (Tue, 13 Apr 2021)" );
	script_tag( name: "creation_date", value: "2016-07-14 12:14:00 +0530 (Thu, 14 Jul 2016)" );
	script_name( "PHP Denial of Service Vulnerability - 01 - Jul16 (Linux)" );
	script_tag( name: "summary", value: "PHP is prone to a denial of service (DoS) vulnerability." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "The flaw is due to script
  'main/php_open_temporary_file.c' does not ensure thread safety." );
	script_tag( name: "impact", value: "Successfully exploiting this issue allow remote
  attackers to cause a denial of service (race condition and heap memory corruption)
  by leveraging an application that performs many temporary-file accesses." );
	script_tag( name: "affected", value: "PHP versions prior to 5.5.28 and 5.6.x
  before 5.6.12 on Linux" );
	script_tag( name: "solution", value: "Update to PHP version 5.5.28, or 5.6.12,
  or later." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "remote_banner_unreliable" );
	script_xref( name: "URL", value: "http://www.php.net/ChangeLog-5.php" );
	script_copyright( "Copyright (C) 2016 Greenbone Networks GmbH" );
	script_category( ACT_GATHER_INFO );
	script_family( "Denial of Service" );
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
if( version_is_less( version: phpVer, test_version: "5.5.28" ) ){
	fix = "5.5.28";
	VULN = TRUE;
}
else {
	if(IsMatchRegexp( phpVer, "^5\\.6" )){
		if(version_in_range( version: phpVer, test_version: "5.6.0", test_version2: "5.6.11" )){
			fix = "5.6.12";
			VULN = TRUE;
		}
	}
}
if(VULN){
	report = report_fixed_ver( installed_version: phpVer, fixed_version: fix );
	security_message( data: report, port: phpPort );
	exit( 0 );
}
exit( 99 );

