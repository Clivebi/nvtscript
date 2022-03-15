CPE = "cpe:/a:php:php";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.103296" );
	script_version( "2021-04-13T14:13:08+0000" );
	script_tag( name: "last_modification", value: "2021-04-13 14:13:08 +0000 (Tue, 13 Apr 2021)" );
	script_tag( name: "creation_date", value: "2011-10-12 15:33:11 +0200 (Wed, 12 Oct 2011)" );
	script_bugtraq_id( 49754 );
	script_cve_id( "CVE-2011-3379" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_name( "PHP 'is_a()' Function Remote File Include Vulnerability" );
	script_category( ACT_GATHER_INFO );
	script_family( "Web application abuses" );
	script_copyright( "Copyright (C) 2011 Greenbone Networks GmbH" );
	script_dependencies( "secpod_php_smb_login_detect.sc", "gb_php_ssh_login_detect.sc", "gb_php_http_detect.sc" );
	script_mandatory_keys( "php/detected" );
	script_xref( name: "URL", value: "http://www.securityfocus.com/bid/49754" );
	script_xref( name: "URL", value: "https://bugs.php.net/bug.php?id=55475" );
	script_xref( name: "URL", value: "http://www.byte.nl/blog/2011/09/23/security-bug-in-is_a-function-in-php-5-3-7-5-3-8/" );
	script_tag( name: "impact", value: "Exploiting this issue may allow an attacker to compromise PHP
  applications using the affected function. This may also result in a
  compromise of the underlying system. Other attacks are also possible." );
	script_tag( name: "affected", value: "PHP 5.3.7 and 5.3.8 are vulnerable." );
	script_tag( name: "solution", value: "Updates are available. Please see the references for more information." );
	script_tag( name: "summary", value: "PHP is prone to a remote file-include vulnerability because it
  fails to properly implement the 'is_a()' function." );
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
if(version_is_equal( version: vers, test_version: "5.3.7" ) || version_is_equal( version: vers, test_version: "5.3.8" )){
	report = report_fixed_ver( installed_version: vers, fixed_version: "5.3.9" );
	security_message( data: report, port: port );
	exit( 0 );
}
exit( 99 );

