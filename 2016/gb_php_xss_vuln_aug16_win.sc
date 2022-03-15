CPE = "cpe:/a:php:php";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.808799" );
	script_version( "2021-04-13T14:13:08+0000" );
	script_cve_id( "CVE-2015-8935" );
	script_bugtraq_id( 92356 );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:P/A:N" );
	script_tag( name: "last_modification", value: "2021-04-13 14:13:08 +0000 (Tue, 13 Apr 2021)" );
	script_tag( name: "creation_date", value: "2016-08-17 15:18:31 +0530 (Wed, 17 Aug 2016)" );
	script_name( "PHP Cross-Site Scripting Vulnerability - Aug16 (Windows)" );
	script_tag( name: "summary", value: "PHP is prone to a cross-site scripting (XSS) vulnerability." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "The flaw is due to  the 'sapi_header_op'
  function in 'main/SAPI.c' script supports deprecated line folding without
  considering browser compatibility." );
	script_tag( name: "impact", value: "Successfully exploiting this issue allows
  remote attackers to conduct cross-site scripting (XSS) attacks against
  Internet Explorer by leveraging '%0A%20' or '%0D%0A%20' mishandling in
  the header function." );
	script_tag( name: "affected", value: "PHP versions before 5.4.38, 5.5.x before
  5.5.22, and 5.6.x before 5.6.6 on Windows" );
	script_tag( name: "solution", value: "Update to PHP version 5.4.38, or 5.5.22,
  or 5.6.6, or later." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_xref( name: "URL", value: "https://bugs.php.net/bug.php?id=68978" );
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
if( version_is_less( version: vers, test_version: "5.4.38" ) ){
	fix = "5.4.38";
	VULN = TRUE;
}
else {
	if( IsMatchRegexp( vers, "^5\\.5" ) ){
		if(version_in_range( version: vers, test_version: "5.5.0", test_version2: "5.5.21" )){
			fix = "5.5.22";
			VULN = TRUE;
		}
	}
	else {
		if(IsMatchRegexp( vers, "^5\\.6" )){
			if(version_in_range( version: vers, test_version: "5.6.0", test_version2: "5.6.5" )){
				fix = "5.6.6";
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

