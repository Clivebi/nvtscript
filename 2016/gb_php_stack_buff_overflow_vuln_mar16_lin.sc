CPE = "cpe:/a:php:php";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.807507" );
	script_version( "2021-04-13T14:13:08+0000" );
	script_cve_id( "CVE-2015-5590", "CVE-2015-8838", "CVE-2015-5589" );
	script_bugtraq_id( 75970, 88763, 75974 );
	script_tag( name: "cvss_base", value: "10.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:C/A:C" );
	script_tag( name: "last_modification", value: "2021-04-13 14:13:08 +0000 (Tue, 13 Apr 2021)" );
	script_tag( name: "creation_date", value: "2016-03-01 16:56:54 +0530 (Tue, 01 Mar 2016)" );
	script_name( "PHP 'phar_fix_filepath' Function Stack Buffer Overflow Vulnerability - Mar16 (Linux)" );
	script_tag( name: "summary", value: "PHP is prone to a stack buffer overflow vulnerability." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "Multiple flaws are due to

  - Inadequate boundary checks on user-supplied input by 'phar_fix_filepath'
    function in 'ext/phar/phar.c' script.

  - Improper validation of file pointer in the 'phar_convert_to_other'
    function in 'ext/phar/phar_object.c' script." );
	script_tag( name: "impact", value: "Successfully exploiting this issue allow
  remote attackers to execute arbitrary code in the context of the PHP process.
  Failed exploit attempts will likely crash the webserver." );
	script_tag( name: "affected", value: "PHP versions before 5.4.43, 5.5.x before
  5.5.27, and 5.6.x before 5.6.11 on Linux" );
	script_tag( name: "solution", value: "Update to PHP version 5.4.43, or 5.5.27, or
  5.6.11 or later." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "remote_banner_unreliable" );
	script_xref( name: "URL", value: "http://www.php.net/ChangeLog-5.php" );
	script_xref( name: "URL", value: "https://bugs.php.net/bug.php?id=69923" );
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
if( version_is_less( version: phpVer, test_version: "5.4.43" ) ){
	fix = "5.4.43";
	VULN = TRUE;
}
else {
	if( IsMatchRegexp( phpVer, "^5\\.6" ) ){
		if(version_is_less( version: phpVer, test_version: "5.6.11" )){
			fix = "5.6.11";
			VULN = TRUE;
		}
	}
	else {
		if(IsMatchRegexp( phpVer, "^5\\.5" )){
			if(version_is_less( version: phpVer, test_version: "5.5.27" )){
				fix = "5.5.27";
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

