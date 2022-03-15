CPE = "cpe:/a:php:php";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.808605" );
	script_version( "2021-09-17T13:01:55+0000" );
	script_cve_id( "CVE-2015-8867", "CVE-2015-8876", "CVE-2015-8873", "CVE-2015-8835" );
	script_bugtraq_id( 87481, 90867, 84426, 90712 );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2021-09-17 13:01:55 +0000 (Fri, 17 Sep 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-02-14 18:48:00 +0000 (Thu, 14 Feb 2019)" );
	script_tag( name: "creation_date", value: "2016-07-14 12:14:00 +0530 (Thu, 14 Jul 2016)" );
	script_name( "PHP Multiple Vulnerabilities - 04 - Jul16 (Windows)" );
	script_tag( name: "summary", value: "PHP is prone to multiple vulnerabilities." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "Multiple flaws exist due to:

  - An improper validation of certain Exception objects in 'Zend/zend_exceptions.c'
    script.

  - The 'openssl_random_pseudo_bytes' function in 'ext/openssl/openssl.c' incorrectly
    relies on the deprecated 'RAND_pseudo_bytes' function." );
	script_tag( name: "impact", value: "Successfully exploiting this issue allow
  remote attackers to cause a denial of service (NULL pointer dereference and
  application crash) or trigger unintended method execution to defeat cryptographic
  protection mechanisms." );
	script_tag( name: "affected", value: "PHP versions prior to 5.4.44, 5.5.x before
  5.5.28, and 5.6.x before 5.6.12 on Windows" );
	script_tag( name: "solution", value: "Update to PHP version 5.4.44,
  or 5.5.28, or 5.6.12, or later." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_xref( name: "URL", value: "http://www.php.net/ChangeLog-5.php" );
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
if( version_is_less( version: phpVer, test_version: "5.4.44" ) ){
	fix = "5.4.44";
	VULN = TRUE;
}
else {
	if( IsMatchRegexp( phpVer, "^5\\.5" ) ){
		if(version_in_range( version: phpVer, test_version: "5.5.0", test_version2: "5.5.27" )){
			fix = "5.5.28";
			VULN = TRUE;
		}
	}
	else {
		if(IsMatchRegexp( phpVer, "^5\\.6" )){
			if(version_in_range( version: phpVer, test_version: "5.6.0", test_version2: "5.6.11" )){
				fix = "5.5.12";
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

