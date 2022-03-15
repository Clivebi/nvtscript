CPE = "cpe:/a:php:php";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.801860" );
	script_version( "2021-04-13T14:13:08+0000" );
	script_tag( name: "last_modification", value: "2021-04-13 14:13:08 +0000 (Tue, 13 Apr 2021)" );
	script_tag( name: "creation_date", value: "2011-03-10 13:33:28 +0100 (Thu, 10 Mar 2011)" );
	script_cve_id( "CVE-2011-0420" );
	script_bugtraq_id( 46429 );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:P" );
	script_name( "PHP 'grapheme_extract()' NULL Pointer Dereference Denial Of Service Vulnerability" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2011 Greenbone Networks GmbH" );
	script_family( "Denial of Service" );
	script_dependencies( "secpod_php_smb_login_detect.sc", "gb_php_ssh_login_detect.sc", "gb_php_http_detect.sc" );
	script_mandatory_keys( "php/detected" );
	script_xref( name: "URL", value: "http://www.exploit-db.com/exploits/16182" );
	script_xref( name: "URL", value: "http://securityreason.com/achievement_securityalert/94" );
	script_xref( name: "URL", value: "http://svn.php.net/viewvc/php/php-src/trunk/ext/intl/grapheme/grapheme_string.c?r1=306449&r2=306448&pathrev=306449" );
	script_xref( name: "URL", value: "http://svn.php.net/viewvc?view=revision&revision=306449" );
	script_tag( name: "impact", value: "Successful exploitation could allows context-dependent attackers to cause a
  denial of service." );
	script_tag( name: "affected", value: "PHP version 5.3.5." );
	script_tag( name: "insight", value: "A flaw is caused by a NULL pointer dereference in the 'grapheme_extract()'
  function in the Internationalization extension (Intl) for ICU which allows
  context-dependent attackers to cause a denial of service via an invalid size
  argument." );
	script_tag( name: "solution", value: "Apply the patch the referenced advisory." );
	script_tag( name: "summary", value: "PHP is prone to a NULL pointer dereference denial of service vulnerability." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "remote_banner_unreliable" );
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
if(version_is_equal( version: phpVer, test_version: "5.3.5" )){
	report = report_fixed_ver( installed_version: phpVer, fixed_version: "5.3.6" );
	security_message( data: report, port: phpPort );
	exit( 0 );
}
exit( 99 );

