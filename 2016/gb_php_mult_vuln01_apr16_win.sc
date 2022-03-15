CPE = "cpe:/a:php:php";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.807806" );
	script_version( "2021-08-10T15:24:26+0000" );
	script_cve_id( "CVE-2016-3142", "CVE-2016-3141" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2021-08-10 15:24:26 +0000 (Tue, 10 Aug 2021)" );
	script_tag( name: "creation_date", value: "2016-04-22 17:24:43 +0530 (Fri, 22 Apr 2016)" );
	script_name( "PHP Multiple Vulnerabilities - 01 - Apr16 (Windows)" );
	script_tag( name: "summary", value: "PHP is prone to multiple vulnerabilities." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "Multiple flaws are due to:

  - A use-after-free error in wddx.c script in the WDDX extension in PHP

  - An error in the phar_parse_zipfile function in zip.c script in the PHAR
  extension in PHP." );
	script_tag( name: "impact", value: "Successfully exploiting this issue allow
  remote attackers to gain access to potentially sensitive information and
  conduct a denial of service (memory corruption and application crash)." );
	script_tag( name: "affected", value: "PHP versions before 5.5.33, and 5.6.x before
  5.6.19 on Windows" );
	script_tag( name: "solution", value: "Update to PHP version 5.5.33 or 5.6.19
  or later." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_xref( name: "URL", value: "https://bugs.php.net/bug.php?id=71587" );
	script_xref( name: "URL", value: "https://bugs.php.net/bug.php?id=71498" );
	script_xref( name: "URL", value: "https://secure.php.net/ChangeLog-5.php" );
	script_copyright( "Copyright (C) 2016 Greenbone Networks GmbH" );
	script_category( ACT_GATHER_INFO );
	script_family( "Web application abuses" );
	script_dependencies( "secpod_php_smb_login_detect.sc", "gb_php_http_detect.sc", "os_detection.sc" );
	script_mandatory_keys( "php/detected", "Host/runs_windows" );
	exit( 0 );
}
require("version_func.inc.sc");
require("host_details.inc.sc");
if(isnull( port = get_app_port( cpe: CPE ) )){
	exit( 0 );
}
if(!vers = get_app_version( cpe: CPE, port: port )){
	exit( 0 );
}
if( version_is_less( version: vers, test_version: "5.5.33" ) ){
	fix = "5.5.33";
	VULN = TRUE;
}
else {
	if(IsMatchRegexp( vers, "^5\\.6" )){
		if(version_in_range( version: vers, test_version: "5.6.0", test_version2: "5.6.18" )){
			fix = "5.6.19";
			VULN = TRUE;
		}
	}
}
if(VULN){
	report = report_fixed_ver( installed_version: vers, fixed_version: fix );
	security_message( data: report, port: port );
	exit( 0 );
}
exit( 99 );

