CPE = "cpe:/a:php:php";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.803778" );
	script_version( "2021-04-13T14:13:08+0000" );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:N/A:N" );
	script_tag( name: "last_modification", value: "2021-04-13 14:13:08 +0000 (Tue, 13 Apr 2021)" );
	script_tag( name: "creation_date", value: "2013-11-26 13:02:20 +0530 (Tue, 26 Nov 2013)" );
	script_name( "PHP 'display_errors' Cross Site Scripting Vulnerability" );
	script_tag( name: "summary", value: "PHP is prone to a cross site scripting vulnerability." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "solution", value: "Update to latest version of PHP." );
	script_tag( name: "insight", value: "The flaw is due to an error in handling 'display_errors', when display_errors
  is set to on and html_errors is set to on." );
	script_tag( name: "affected", value: "PHP versions 5.3.10 and 5.4.0" );
	script_tag( name: "impact", value: "Successful exploitation will allow remote attackers to insert arbitrary HTML
  and script code, which will be executed in a user's browser session in the
  context of an affected site." );
	script_xref( name: "URL", value: "http://packetstormsecurity.com/files/111695/" );
	script_xref( name: "URL", value: "http://dl.packetstormsecurity.net/1204-exploits/php-xss.txt" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2013 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "secpod_php_smb_login_detect.sc", "gb_php_ssh_login_detect.sc", "gb_php_http_detect.sc" );
	script_mandatory_keys( "php/detected" );
	script_tag( name: "qod_type", value: "remote_banner_unreliable" );
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
if(version_is_equal( version: phpVer, test_version: "5.3.10" ) || version_is_equal( version: phpVer, test_version: "5.4.0" )){
	report = report_fixed_ver( installed_version: phpVer, fixed_version: "5.3.11/5.4.1" );
	security_message( data: report, port: phpPort );
	exit( 0 );
}
exit( 99 );

