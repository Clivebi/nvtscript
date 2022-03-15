CPE = "cpe:/a:php:php";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.812073" );
	script_version( "2021-09-10T10:01:38+0000" );
	script_cve_id( "CVE-2017-16642" );
	script_bugtraq_id( 101745 );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:N/A:N" );
	script_tag( name: "last_modification", value: "2021-09-10 10:01:38 +0000 (Fri, 10 Sep 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-08-19 11:15:00 +0000 (Mon, 19 Aug 2019)" );
	script_tag( name: "creation_date", value: "2017-11-09 18:55:09 +0530 (Thu, 09 Nov 2017)" );
	script_name( "PHP 'timelib_meridian' Heap Based Buffer Overflow Vulnerability (Linux)" );
	script_tag( name: "summary", value: "PHP is prone to a heap buffer overflow vulnerability." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "The flaw exists due to an error in the date
  extension's 'timelib_meridian' handling of 'front of' and 'back of' directives." );
	script_tag( name: "impact", value: "Successfully exploiting this issue allow
  attacker to execute arbitrary code with elevated privileges within the context
  of a privileged process." );
	script_tag( name: "affected", value: "PHP versions before 5.6.32, 7.x before 7.0.25,
  and 7.1.x before 7.1.11" );
	script_tag( name: "solution", value: "Update to PHP version 5.6.32, 7.0.25, 7.1.11,
  or later." );
	script_xref( name: "URL", value: "http://php.net/ChangeLog-5.php" );
	script_xref( name: "URL", value: "http://php.net/ChangeLog-7.php" );
	script_xref( name: "URL", value: "https://bugs.php.net/bug.php?id=75055" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "remote_banner_unreliable" );
	script_copyright( "Copyright (C) 2017 Greenbone Networks GmbH" );
	script_category( ACT_GATHER_INFO );
	script_family( "Buffer overflow" );
	script_dependencies( "gb_php_ssh_login_detect.sc", "gb_php_http_detect.sc", "os_detection.sc" );
	script_mandatory_keys( "php/detected", "Host/runs_unixoide" );
	exit( 0 );
}
require("version_func.inc.sc");
require("host_details.inc.sc");
if(isnull( port = get_app_port( cpe: CPE ) )){
	exit( 0 );
}
if(!infos = get_app_version_and_location( cpe: CPE, port: port, exit_no_version: TRUE )){
	exit( 0 );
}
vers = infos["version"];
path = infos["location"];
if( version_is_less( version: vers, test_version: "5.6.32" ) ){
	fix = "5.6.32";
}
else {
	if( version_in_range( version: vers, test_version: "7.0", test_version2: "7.0.24" ) ){
		fix = "7.0.25";
	}
	else {
		if(IsMatchRegexp( vers, "^7\\.1" ) && version_is_less( version: vers, test_version: "7.1.11" )){
			fix = "7.1.11";
		}
	}
}
if(fix){
	report = report_fixed_ver( installed_version: vers, fixed_version: fix, install_path: path );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

