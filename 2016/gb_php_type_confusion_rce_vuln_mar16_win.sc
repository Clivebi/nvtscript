CPE = "cpe:/a:php:php";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.807091" );
	script_version( "2021-04-13T14:13:08+0000" );
	script_cve_id( "CVE-2015-6836" );
	script_bugtraq_id( 76644 );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2021-04-13 14:13:08 +0000 (Tue, 13 Apr 2021)" );
	script_tag( name: "creation_date", value: "2016-03-01 16:56:54 +0530 (Tue, 01 Mar 2016)" );
	script_name( "PHP 'serialize_function_call' Function Type Confusion Vulnerability - Mar16 (Windows)" );
	script_tag( name: "summary", value: "PHP is prone to a remote code execution (RCE) vulnerability." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "The flaw is due to 'SoapClient __call'
  method in 'ext/soap/soap.c' scripr does not properly manage headers." );
	script_tag( name: "impact", value: "Successfully exploiting this issue allow
  remote attackers to execute arbitrary code in the context of the user
  running the affected application. Failed exploit attempts will likely cause
  a denial-of-service condition." );
	script_tag( name: "affected", value: "PHP versions before 5.4.45, 5.5.x before
  5.5.29, and 5.6.x before 5.6.13 on Windows" );
	script_tag( name: "solution", value: "Update to PHP version 5.4.45, or 5.5.29, or
  5.6.13 or later." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_xref( name: "URL", value: "http://www.php.net/ChangeLog-5.php" );
	script_xref( name: "URL", value: "https://bugs.php.net/bug.php?id=70388" );
	script_copyright( "Copyright (C) 2016 Greenbone Networks GmbH" );
	script_category( ACT_GATHER_INFO );
	script_family( "Web application abuses" );
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
if( version_is_less( version: phpVer, test_version: "5.4.45" ) ){
	fix = "5.4.45";
	VULN = TRUE;
}
else {
	if( IsMatchRegexp( phpVer, "^5\\.6" ) ){
		if(version_is_less( version: phpVer, test_version: "5.6.13" )){
			fix = "5.6.13";
			VULN = TRUE;
		}
	}
	else {
		if(IsMatchRegexp( phpVer, "^5\\.5" )){
			if(version_is_less( version: phpVer, test_version: "5.5.29" )){
				fix = "5.5.29";
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

