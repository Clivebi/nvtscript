CPE = "cpe:/a:php:php";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.808198" );
	script_version( "2021-08-10T15:24:26+0000" );
	script_cve_id( "CVE-2016-4070", "CVE-2016-4071", "CVE-2016-4072", "CVE-2016-4073", "CVE-2015-8865" );
	script_bugtraq_id( 85800, 85801, 85802, 85991, 85993 );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2021-08-10 15:24:26 +0000 (Tue, 10 Aug 2021)" );
	script_tag( name: "creation_date", value: "2016-07-14 12:14:00 +0530 (Thu, 14 Jul 2016)" );
	script_name( "PHP Multiple Vulnerabilities - 01 - Jul16 (Windows)" );
	script_tag( name: "summary", value: "PHP is prone to multiple vulnerabilities." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "Multiple flaws are due to:

  - Multiple integer overflows in the mbfl_strcut function in
    'ext/mbstring/libmbfl/mbfl/mbfilter.c' script.

  - Format string vulnerability in the php_snmp_error function in
    'ext/snmp/snmp.c' script.

  - An improper handling of '\\0' characters by the 'phar_analyze_path' function
    in 'ext/phar/phar.c' script.

  - An integer overflow in the 'php_raw_url_encode' function in
    'ext/standard/url.c' script.

  - An improper handling of continuation-level jumps in 'file_check_mem'
    function in 'funcs.c' script." );
	script_tag( name: "impact", value: "Successfully exploiting this issue allow
  remote attackers to cause a denial of service (buffer overflow and application
  crash) or possibly execute arbitrary code." );
	script_tag( name: "affected", value: "PHP versions prior to 5.5.34, 5.6.x before
  5.6.20, and 7.x before 7.0.5 on Windows" );
	script_tag( name: "solution", value: "Update to PHP version 5.5.34, or 5.6.20,
  or 7.0.5, or later." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_xref( name: "URL", value: "http://www.php.net/ChangeLog-5.php" );
	script_xref( name: "URL", value: "http://www.php.net/ChangeLog-7.php" );
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
if( version_is_less( version: phpVer, test_version: "5.5.34" ) ){
	fix = "5.5.34";
	VULN = TRUE;
}
else {
	if( IsMatchRegexp( phpVer, "^5\\.6" ) ){
		if(version_in_range( version: phpVer, test_version: "5.6.0", test_version2: "5.6.19" )){
			fix = "5.6.20";
			VULN = TRUE;
		}
	}
	else {
		if(IsMatchRegexp( phpVer, "^7\\.0" )){
			if(version_in_range( version: phpVer, test_version: "7.0", test_version2: "7.0.4" )){
				fix = "7.0.5";
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

