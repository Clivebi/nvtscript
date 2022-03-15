CPE = "cpe:/a:php:php";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.807503" );
	script_version( "2021-08-10T15:24:26+0000" );
	script_cve_id( "CVE-2015-6831", "CVE-2015-6832", "CVE-2015-6833" );
	script_bugtraq_id( 76737, 76739, 76735 );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2021-08-10 15:24:26 +0000 (Tue, 10 Aug 2021)" );
	script_tag( name: "creation_date", value: "2016-03-01 16:56:54 +0530 (Tue, 01 Mar 2016)" );
	script_name( "PHP Multiple Vulnerabilities - 01 - Mar16 (Linux)" );
	script_tag( name: "summary", value: "PHP is prone to multiple vulnerabilities." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "Multiple flaws are due to:

  - The multiple use-after-free vulnerabilities in SPL unserialize implementation.

  - An insufficient validation of user supplied input by 'phar/phar_object.c'
    script." );
	script_tag( name: "impact", value: "Successfully exploiting this issue allow
  remote attackers to execute arbitrary code and to create or overwrite arbitrary
  files on the system and this may lead to launch further attacks." );
	script_tag( name: "affected", value: "PHP versions before 5.4.44, 5.5.x before
  5.5.28, and 5.6.x before 5.6.12 on Linux" );
	script_tag( name: "solution", value: "Update to PHP version 5.4.44 or 5.5.28 or
  5.6.12 or later." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "remote_banner_unreliable" );
	script_xref( name: "URL", value: "https://bugs.php.net/bug.php?id=70068" );
	script_xref( name: "URL", value: "http://www.openwall.com/lists/oss-security/2015/08/19/3" );
	script_copyright( "Copyright (C) 2016 Greenbone Networks GmbH" );
	script_category( ACT_GATHER_INFO );
	script_family( "Web application abuses" );
	script_dependencies( "gb_php_ssh_login_detect.sc", "gb_php_http_detect.sc", "os_detection.sc" );
	script_mandatory_keys( "php/detected", "Host/runs_unixoide" );
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
if( version_is_less( version: vers, test_version: "5.4.44" ) ){
	fix = "5.4.44";
	VULN = TRUE;
}
else {
	if( IsMatchRegexp( vers, "^5\\.6" ) ){
		if(version_in_range( version: vers, test_version: "5.6.0", test_version2: "5.6.11" )){
			fix = "5.6.12";
			VULN = TRUE;
		}
	}
	else {
		if(IsMatchRegexp( vers, "^5\\.5" )){
			if(version_in_range( version: vers, test_version: "5.5.0", test_version2: "5.5.27" )){
				fix = "5.5.28";
				VULN = TRUE;
			}
		}
	}
}
if(VULN){
	report = report_fixed_ver( installed_version: vers, fixed_version: fix );
	security_message( data: report, port: port );
	exit( 0 );
}
exit( 99 );

