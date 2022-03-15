CPE = "cpe:/a:php:php";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.100726" );
	script_version( "2021-04-13T14:13:08+0000" );
	script_tag( name: "last_modification", value: "2021-04-13 14:13:08 +0000 (Tue, 13 Apr 2021)" );
	script_tag( name: "creation_date", value: "2010-08-02 14:28:14 +0200 (Mon, 02 Aug 2010)" );
	script_bugtraq_id( 41991 );
	script_cve_id( "CVE-2010-2531", "CVE-2010-2484" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:N/A:N" );
	script_name( "PHP Versions Prior to 5.3.3/5.2.14 Multiple Vulnerabilities" );
	script_category( ACT_GATHER_INFO );
	script_family( "Web application abuses" );
	script_copyright( "Copyright (C) 2010 Greenbone Networks GmbH" );
	script_dependencies( "secpod_php_smb_login_detect.sc", "gb_php_ssh_login_detect.sc", "gb_php_http_detect.sc" );
	script_mandatory_keys( "php/detected" );
	script_xref( name: "URL", value: "https://www.securityfocus.com/bid/41991" );
	script_xref( name: "URL", value: "http://www.php.net/ChangeLog-5.php#5.3.3" );
	script_tag( name: "impact", value: "An attacker can exploit these issues to execute arbitrary code, crash
  the affected application, gain access to sensitive information and
  bypass security restrictions. Other attacks are also possible." );
	script_tag( name: "affected", value: "PHP 5.3 (Prior to 5.3.3) PHP 5.2 (Prior to 5.2.14)" );
	script_tag( name: "solution", value: "Updates are available. Please see the references for more information." );
	script_tag( name: "summary", value: "PHP is prone to multiple security vulnerabilities." );
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
if( IsMatchRegexp( vers, "^5\\.2" ) ){
	if(version_is_less( version: vers, test_version: "5.2.14" )){
		vuln = TRUE;
		fix = "5.2.14";
	}
}
else {
	if(IsMatchRegexp( vers, "^5\\.3" )){
		if(version_is_less( version: vers, test_version: "5.3.3" )){
			vuln = TRUE;
			fix = "5.3.3";
		}
	}
}
if(vuln){
	report = report_fixed_ver( installed_version: vers, fixed_version: fix );
	security_message( data: report, port: port );
	exit( 0 );
}
exit( 99 );

