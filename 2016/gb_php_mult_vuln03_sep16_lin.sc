CPE = "cpe:/a:php:php";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.809317" );
	script_version( "2021-08-10T15:24:26+0000" );
	script_cve_id( "CVE-2016-7412", "CVE-2016-7413", "CVE-2016-7414", "CVE-2016-7416", "CVE-2016-7417", "CVE-2016-7418" );
	script_bugtraq_id( 93005, 93006, 93004, 93022, 93008, 93007, 93011 );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2021-08-10 15:24:26 +0000 (Tue, 10 Aug 2021)" );
	script_tag( name: "creation_date", value: "2016-09-12 18:19:30 +0530 (Mon, 12 Sep 2016)" );
	script_name( "PHP Multiple Vulnerabilities - 03 - Sep16 (Linux)" );
	script_tag( name: "summary", value: "PHP is prone to multiple vulnerabilities." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "Multiple flaws are due to:

  - Use-after-free vulnerability in the 'wddx_stack_destroy' function
    in 'ext/wddx/wddx.c' script.

  - Improper varification of a BIT field has the UNSIGNED_FLAG flag
    in 'ext/mysqlnd/mysqlnd_wireprotocol.c' script.

  - The ZIP signature-verification feature does not ensure that the
    uncompressed_filesize field is large enough.

  - The script 'ext/spl/spl_array.c' proceeds with SplArray unserialization
    without validating a return value and data type.

  - The script 'ext/intl/msgformat/msgformat_format.c' does not properly restrict
    the locale length provided to the Locale class in the ICU library.

  - An error in the php_wddx_push_element function in ext/wddx/wddx.c." );
	script_tag( name: "impact", value: "Successfully exploiting this issue allow
  remote attackers to cause a denial of service, or possibly have unspecified
  other impact." );
	script_tag( name: "affected", value: "PHP versions prior to 5.6.25 and
  7.x before 7.0.10 on Linux" );
	script_tag( name: "solution", value: "Update to PHP version 5.6.25, or 7.0.10,
  or later." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "remote_banner_unreliable" );
	script_xref( name: "URL", value: "http://www.php.net/ChangeLog-7.php" );
	script_xref( name: "URL", value: "http://www.php.net/ChangeLog-5.php" );
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
if( version_is_less( version: phpVer, test_version: "5.6.26" ) ){
	fix = "5.6.26";
	VULN = TRUE;
}
else {
	if(IsMatchRegexp( phpVer, "^7\\.0" )){
		if(version_in_range( version: phpVer, test_version: "7.0", test_version2: "7.0.10" )){
			fix = "7.0.11";
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

