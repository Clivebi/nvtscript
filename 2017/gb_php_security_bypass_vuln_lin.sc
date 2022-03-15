CPE = "cpe:/a:php:php";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.811489" );
	script_version( "2021-09-13T12:01:42+0000" );
	script_cve_id( "CVE-2016-10397" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:P/A:N" );
	script_tag( name: "last_modification", value: "2021-09-13 12:01:42 +0000 (Mon, 13 Sep 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2018-01-14 02:29:00 +0000 (Sun, 14 Jan 2018)" );
	script_tag( name: "creation_date", value: "2017-07-13 16:38:21 +0530 (Thu, 13 Jul 2017)" );
	script_name( "PHP 'URL checks' Security Bypass Vulnerability Jul17 (Linux)" );
	script_tag( name: "summary", value: "PHP is prone to a security bypass vulnerability." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "The flaw exists due to incorrect handling of
  various URI components in the URL parser." );
	script_tag( name: "impact", value: "Successfully exploiting this issue allow
  an attacker to bypass hostname-specific URL checks." );
	script_tag( name: "affected", value: "PHP versions before 5.6.28, 7.x before 7.0.13" );
	script_tag( name: "solution", value: "Update to PHP version 5.6.28, 7.0.13,
  or later." );
	script_xref( name: "URL", value: "http://www.php.net/ChangeLog-5.php" );
	script_xref( name: "URL", value: "http://www.php.net/ChangeLog-7.php" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "remote_banner_unreliable" );
	script_copyright( "Copyright (C) 2017 Greenbone Networks GmbH" );
	script_category( ACT_GATHER_INFO );
	script_family( "Web application abuses" );
	script_dependencies( "gb_php_ssh_login_detect.sc", "gb_php_http_detect.sc", "os_detection.sc" );
	script_mandatory_keys( "php/detected", "Host/runs_unixoide" );
	exit( 0 );
}
require("version_func.inc.sc");
require("host_details.inc.sc");
if(isnull( phpport = get_app_port( cpe: CPE ) )){
	exit( 0 );
}
if(!vers = get_app_version( cpe: CPE, port: phpport )){
	exit( 0 );
}
if( version_is_less( version: vers, test_version: "5.6.28" ) ){
	fix = "5.6.28";
}
else {
	if(version_in_range( version: vers, test_version: "7.0", test_version2: "7.0.12" )){
		fix = "7.0.13";
	}
}
if(fix){
	report = report_fixed_ver( installed_version: vers, fixed_version: fix );
	security_message( port: phpport, data: report );
	exit( 0 );
}
exit( 99 );

