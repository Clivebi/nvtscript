CPE = "cpe:/a:php:php";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.900872" );
	script_version( "2021-09-01T12:57:33+0000" );
	script_tag( name: "last_modification", value: "2021-09-01 12:57:33 +0000 (Wed, 01 Sep 2021)" );
	script_tag( name: "creation_date", value: "2009-09-29 09:16:03 +0200 (Tue, 29 Sep 2009)" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:P" );
	script_cve_id( "CVE-2009-3294" );
	script_bugtraq_id( 36449 );
	script_name( "PHP 'tsrm_win32.c' Denial Of Service Vulnerability (Windows)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2009 Greenbone Networks GmbH" );
	script_family( "Denial of Service" );
	script_dependencies( "secpod_php_smb_login_detect.sc", "gb_php_http_detect.sc", "os_detection.sc" );
	script_mandatory_keys( "php/detected", "Host/runs_windows" );
	script_xref( name: "URL", value: "http://en.securitylab.ru/nvd/383831.php" );
	script_xref( name: "URL", value: "http://downloads.securityfocus.com/vulnerabilities/exploits/31064.php" );
	script_tag( name: "impact", value: "Successful exploitation will allow attackers to cause Denial of Service in
  the victim's system." );
	script_tag( name: "affected", value: "PHP version prior to 5.2.11 on Windows." );
	script_tag( name: "insight", value: "An error occurs in popem 'API' function in TSRM/tsrm_win32.c, when running on
  certain Windows operating systems. It can be caused via a crafted 'e' or 'er'
  string in the second argument (aka mode), possibly related to the '_fdopen'
  function in the Microsoft C runtime library." );
	script_tag( name: "solution", value: "Update to version 5.2.11 or later." );
	script_tag( name: "summary", value: "PHP is prone to a Denial of Service vulnerability." );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_tag( name: "solution_type", value: "VendorFix" );
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
if(version_is_less( version: phpVer, test_version: "5.2.11" )){
	report = report_fixed_ver( installed_version: phpVer, fixed_version: "5.2.11" );
	security_message( data: report, port: phpPort );
	exit( 0 );
}
exit( 99 );

