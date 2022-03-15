CPE = "cpe:/a:php:php";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.100511" );
	script_version( "2021-04-13T14:13:08+0000" );
	script_tag( name: "last_modification", value: "2021-04-13 14:13:08 +0000 (Tue, 13 Apr 2021)" );
	script_tag( name: "creation_date", value: "2010-02-27 19:39:22 +0100 (Sat, 27 Feb 2010)" );
	script_bugtraq_id( 38182, 38431, 38430 );
	script_cve_id( "CVE-2010-1128", "CVE-2010-1129" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_name( "PHP < 5.2.13 Multiple Vulnerabilities" );
	script_category( ACT_GATHER_INFO );
	script_family( "Web application abuses" );
	script_copyright( "Copyright (C) 2010 Greenbone Networks GmbH" );
	script_dependencies( "secpod_php_smb_login_detect.sc", "gb_php_ssh_login_detect.sc", "gb_php_http_detect.sc" );
	script_mandatory_keys( "php/detected" );
	script_xref( name: "URL", value: "http://www.securityfocus.com/bid/38182" );
	script_xref( name: "URL", value: "http://www.securityfocus.com/bid/38431" );
	script_xref( name: "URL", value: "http://www.securityfocus.com/bid/38430" );
	script_xref( name: "URL", value: "http://securityreason.com/achievement_securityalert/82" );
	script_xref( name: "URL", value: "http://www.php.net/releases/5_2_13.php" );
	script_xref( name: "URL", value: "http://svn.php.net/viewvc/php/php-src/branches/PHP_5_2/ext/session/session.c?r1=293036&r2=294272" );
	script_xref( name: "URL", value: "http://svn.php.net/viewvc/php/php-src/branches/PHP_5_3/ext/session/session.c?r1=293036&r2=294272" );
	script_tag( name: "affected", value: "PHP versions prior to 5.2.13 are affected." );
	script_tag( name: "insight", value: "Multiple vulnerabilities exist due to:

  1. A 'safe_mode' restriction-bypass vulnerability. Successful exploits
  could allow an attacker to write session files in arbitrary directions.

  2. A 'safe_mode' restriction-bypass vulnerability. Successful exploits
  could allow an attacker to access files in unauthorized locations or
  create files in any writable directory.

  3. An unspecified security vulnerability that affects LCG entropy." );
	script_tag( name: "solution", value: "Updates are available. Please see the references for details." );
	script_tag( name: "summary", value: "The remote web server has installed a PHP Version which is prone to
  Multiple Vulnerabilities." );
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
if(version_is_less( version: vers, test_version: "5.2.13" )){
	report = report_fixed_ver( installed_version: vers, fixed_version: "5.2.13" );
	security_message( data: report, port: port );
	exit( 0 );
}
exit( 99 );

