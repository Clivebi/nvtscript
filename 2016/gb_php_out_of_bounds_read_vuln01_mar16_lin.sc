CPE = "cpe:/a:php:php";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.807504" );
	script_version( "2021-09-20T12:38:59+0000" );
	script_cve_id( "CVE-2016-1903" );
	script_bugtraq_id( 79916 );
	script_tag( name: "cvss_base", value: "6.4" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:N/A:P" );
	script_tag( name: "last_modification", value: "2021-09-20 12:38:59 +0000 (Mon, 20 Sep 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2018-01-05 02:30:00 +0000 (Fri, 05 Jan 2018)" );
	script_tag( name: "creation_date", value: "2016-03-01 16:56:54 +0530 (Tue, 01 Mar 2016)" );
	script_name( "PHP Out of Bounds Read Memory Corruption Vulnerability - 01 - Mar16 (Linux)" );
	script_tag( name: "summary", value: "PHP is prone to an out-of-bounds read memory corruption vulnerability." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "The flaw is due to memory corruption
  vulnerability via a large 'bgd_color' argument to the 'imagerotate' function
  in 'ext/gd/libgd/gd_interpolation.c' script." );
	script_tag( name: "impact", value: "Successfully exploiting this issue allow
  remote attackers to obtain sensitive information or cause a denial-of-service
  condition." );
	script_tag( name: "affected", value: "PHP versions before 5.5.31, 5.6.x before
  5.6.17, and 7.x before 7.0.2 on Linux" );
	script_tag( name: "solution", value: "Update to PHP version 5.5.31, or 5.6.17 or
  7.0.2 or later." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "remote_banner_unreliable" );
	script_xref( name: "URL", value: "https://bugs.php.net/bug.php?id=70976" );
	script_xref( name: "URL", value: "http://www.openwall.com/lists/oss-security/2016/01/14/8" );
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
if( version_is_less( version: vers, test_version: "5.5.31" ) ){
	fix = "5.5.31";
	VULN = TRUE;
}
else {
	if( IsMatchRegexp( vers, "^5\\.6" ) ){
		if(version_is_less( version: vers, test_version: "5.6.17" )){
			fix = "5.6.17";
			VULN = TRUE;
		}
	}
	else {
		if(IsMatchRegexp( vers, "^7" )){
			if(version_is_less( version: vers, test_version: "7.0.2" )){
				fix = "7.0.2";
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

