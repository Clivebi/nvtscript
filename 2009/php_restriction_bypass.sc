CPE = "cpe:/a:php:php";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.100281" );
	script_version( "2021-04-13T14:13:08+0000" );
	script_tag( name: "last_modification", value: "2021-04-13 14:13:08 +0000 (Tue, 13 Apr 2021)" );
	script_tag( name: "creation_date", value: "2009-10-01 18:57:31 +0200 (Thu, 01 Oct 2009)" );
	script_bugtraq_id( 36555, 36554 );
	script_cve_id( "CVE-2009-3557", "CVE-2009-3558" );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_name( "PHP Multiple Restriction-Bypass Vulnerabilities" );
	script_category( ACT_GATHER_INFO );
	script_family( "Web application abuses" );
	script_copyright( "Copyright (C) 2009 Greenbone Networks GmbH" );
	script_dependencies( "secpod_php_smb_login_detect.sc", "gb_php_ssh_login_detect.sc", "gb_php_http_detect.sc" );
	script_mandatory_keys( "php/detected" );
	script_xref( name: "URL", value: "http://www.securityfocus.com/bid/36555" );
	script_xref( name: "URL", value: "http://www.securityfocus.com/bid/36554" );
	script_xref( name: "URL", value: "http://svn.php.net/viewvc/php/php-src/branches/PHP_5_2/ext/standard/file.c?view=log" );
	script_xref( name: "URL", value: "http://svn.php.net/viewvc/php/php-src/branches/PHP_5_3/ext/standard/file.c?view=log" );
	script_xref( name: "URL", value: "http://svn.php.net/viewvc/php/php-src/branches/PHP_5_2/ext/posix/posix.c?view=log" );
	script_xref( name: "URL", value: "http://svn.php.net/viewvc/php/php-src/branches/PHP_5_3/ext/posix/posix.c?view=log" );
	script_xref( name: "URL", value: "http://securityreason.com/securityalert/6601" );
	script_xref( name: "URL", value: "http://securityreason.com/securityalert/6600" );
	script_tag( name: "summary", value: "PHP is prone to a 'safe_mode' and to a 'open_basedir' restriction-bypass vulnerability." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "This vulnerability would be an issue in shared-hosting configurations
  where multiple users can create and execute arbitrary PHP script code. The 'safe_mode'
  and the 'open_basedir' restrictions are assumed to isolate users from each other." );
	script_tag( name: "impact", value: "Successful exploits could allow an attacker to access files in unauthorized locations or
  create files in any writable directory and in unauthorized locations." );
	script_tag( name: "affected", value: "PHP 5.2.11 and 5.3.0 are vulnerable. Other versions may also be affected." );
	script_tag( name: "solution", value: "Updates are available. Please see the references for details." );
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
if(version_is_equal( version: vers, test_version: "5.2.11" ) || version_is_equal( version: vers, test_version: "5.3.0" )){
	report = report_fixed_ver( installed_version: vers, fixed_version: "5.2.12/5.3.1" );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

