CPE = "cpe:/a:php:php";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.100601" );
	script_version( "2021-04-13T14:13:08+0000" );
	script_tag( name: "last_modification", value: "2021-04-13 14:13:08 +0000 (Tue, 13 Apr 2021)" );
	script_tag( name: "creation_date", value: "2010-04-23 13:12:25 +0200 (Fri, 23 Apr 2010)" );
	script_bugtraq_id( 23169 );
	script_cve_id( "CVE-2007-1777" );
	script_name( "PHP Zip_Entry_Read() Integer Overflow Vulnerability" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_category( ACT_GATHER_INFO );
	script_family( "Web application abuses" );
	script_copyright( "Copyright (C) 2010 Greenbone Networks GmbH" );
	script_dependencies( "secpod_php_smb_login_detect.sc", "gb_php_ssh_login_detect.sc", "gb_php_http_detect.sc" );
	script_mandatory_keys( "php/detected" );
	script_xref( name: "URL", value: "http://www.securityfocus.com/bid/23169" );
	script_xref( name: "URL", value: "http://www.php-security.org/MOPB/MOPB-35-2007.html" );
	script_tag( name: "impact", value: "Exploiting this issue may allow attackers to execute arbitrary machine
  code in the context of the affected application. Failed exploit
  attempts will likely result in a denial-of-service condition." );
	script_tag( name: "affected", value: "This issue affects versions prior to PHP 4.4.5." );
	script_tag( name: "solution", value: "Reports indicate that PHP 4.4.5 addresses this issue. Please contact
  the vendor for more information." );
	script_tag( name: "summary", value: "PHP is prone to an integer-overflow vulnerability because it
  fails to ensure that integer values aren't overrun. Attackers
  may exploit this issue to cause a heap-based buffer overflow." );
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
if(version_is_less( version: vers, test_version: "4.4.5" )){
	report = report_fixed_ver( installed_version: vers, fixed_version: "4.4.5" );
	security_message( data: report, port: port );
	exit( 0 );
}
exit( 99 );

