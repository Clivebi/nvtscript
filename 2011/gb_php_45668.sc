CPE = "cpe:/a:php:php";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.103020" );
	script_version( "2021-04-13T14:13:08+0000" );
	script_tag( name: "last_modification", value: "2021-04-13 14:13:08 +0000 (Tue, 13 Apr 2021)" );
	script_tag( name: "creation_date", value: "2011-01-10 13:28:19 +0100 (Mon, 10 Jan 2011)" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:P" );
	script_cve_id( "CVE-2010-4645" );
	script_bugtraq_id( 45668 );
	script_name( "PHP 'zend_strtod()' Function Floating-Point Value Denial of Service Vulnerability" );
	script_category( ACT_GATHER_INFO );
	script_family( "Denial of Service" );
	script_copyright( "Copyright (C) 2011 Greenbone Networks GmbH" );
	script_dependencies( "secpod_php_smb_login_detect.sc", "gb_php_ssh_login_detect.sc", "gb_php_http_detect.sc" );
	script_mandatory_keys( "php/detected" );
	script_xref( name: "URL", value: "https://www.securityfocus.com/bid/45668" );
	script_xref( name: "URL", value: "http://bugs.php.net/bug.php?id=53632" );
	script_xref( name: "URL", value: "http://svn.php.net/viewvc/?view=revision&revision=307119" );
	script_xref( name: "URL", value: "http://svn.php.net/viewvc?view=revision&revision=307095" );
	script_xref( name: "URL", value: "http://www.exploringbinary.com/php-hangs-on-numeric-value-2-2250738585072011e-308/" );
	script_tag( name: "impact", value: "Successful attacks will cause applications written in PHP to hang,
  creating a denial-of-service condition." );
	script_tag( name: "affected", value: "PHP 5.3.3 is vulnerable. Other versions may also be affected." );
	script_tag( name: "insight", value: "The vulnerability is due to the Floating-Point Value that exist in zend_strtod function" );
	script_tag( name: "solution", value: "Updates are available. Please see the references for more details." );
	script_tag( name: "summary", value: "PHP is prone to a remote denial-of-service vulnerability." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "remote_banner_unreliable" );
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
if(version_in_range( version: vers, test_version: "5.3", test_version2: "5.3.4" ) || version_in_range( version: vers, test_version: "5.2", test_version2: "5.2.16" )){
	report = report_fixed_ver( installed_version: vers, fixed_version: "5.2.17/5.3.5" );
	security_message( data: report, port: port );
	exit( 0 );
}
exit( 99 );

