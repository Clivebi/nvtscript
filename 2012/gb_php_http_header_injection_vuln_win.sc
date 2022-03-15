CPE = "cpe:/a:php:php";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.802966" );
	script_version( "2021-04-13T14:13:08+0000" );
	script_cve_id( "CVE-2012-4388", "CVE-2011-1398" );
	script_bugtraq_id( 55527, 55297 );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:P/A:N" );
	script_tag( name: "last_modification", value: "2021-04-13 14:13:08 +0000 (Tue, 13 Apr 2021)" );
	script_tag( name: "creation_date", value: "2012-09-24 18:58:41 +0530 (Mon, 24 Sep 2012)" );
	script_name( "PHP 'main/SAPI.c' HTTP Header Injection Vulnerability" );
	script_xref( name: "URL", value: "http://openwall.com/lists/oss-security/2012/09/02/1" );
	script_xref( name: "URL", value: "http://openwall.com/lists/oss-security/2012/09/07/3" );
	script_xref( name: "URL", value: "http://article.gmane.org/gmane.comp.php.devel/70584" );
	script_xref( name: "URL", value: "http://openwall.com/lists/oss-security/2012/09/05/15" );
	script_xref( name: "URL", value: "http://security-tracker.debian.org/tracker/CVE-2012-4388" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2012 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "secpod_php_smb_login_detect.sc", "gb_php_http_detect.sc", "os_detection.sc" );
	script_mandatory_keys( "php/detected", "Host/runs_windows" );
	script_tag( name: "impact", value: "Successful exploitation could allows remote attackers to insert arbitrary
  headers, conduct cross-site request-forgery, cross-site scripting,
  HTML-injection, and other attacks." );
	script_tag( name: "affected", value: "PHP version prior to 5.3.11, PHP version 5.4.x through 5.4.0RC2 on Windows" );
	script_tag( name: "insight", value: "The sapi_header_op function in main/SAPI.c in PHP does not properly determine
  a pointer during checks for %0D sequences." );
	script_tag( name: "solution", value: "Update to PHP 5.4.1 RC1 or later." );
	script_tag( name: "summary", value: "PHP is prone to an HTTP header injection vulnerability." );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_tag( name: "solution_type", value: "VendorFix" );
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
if(version_is_less( version: vers, test_version: "5.3.11" ) || version_in_range( version: vers, test_version: "5.4.0", test_version2: "5.4.0.rc2" )){
	report = report_fixed_ver( installed_version: vers, fixed_version: "5.3.11/5.4.1 RC1" );
	security_message( data: report, port: port );
	exit( 0 );
}
exit( 99 );

