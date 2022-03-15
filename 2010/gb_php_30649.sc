CPE = "cpe:/a:php:php";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.100583" );
	script_version( "2021-04-13T14:13:08+0000" );
	script_tag( name: "last_modification", value: "2021-04-13 14:13:08 +0000 (Tue, 13 Apr 2021)" );
	script_tag( name: "creation_date", value: "2010-04-19 20:46:01 +0200 (Mon, 19 Apr 2010)" );
	script_bugtraq_id( 30649 );
	script_cve_id( "CVE-2008-3659", "CVE-2008-3658" );
	script_name( "PHP Multiple Buffer Overflow Vulnerabilities" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_category( ACT_GATHER_INFO );
	script_family( "Web application abuses" );
	script_copyright( "Copyright (C) 2010 Greenbone Networks GmbH" );
	script_dependencies( "secpod_php_smb_login_detect.sc", "gb_php_ssh_login_detect.sc", "gb_php_http_detect.sc" );
	script_mandatory_keys( "php/detected" );
	script_xref( name: "URL", value: "http://www.securityfocus.com/bid/30649" );
	script_xref( name: "URL", value: "http://www.php.net/ChangeLog-5.php#5.2.8" );
	script_xref( name: "URL", value: "http://www.php.net/archive/2008.php#id2008-08-07-1" );
	script_xref( name: "URL", value: "http://support.avaya.com/elmodocs2/security/ASA-2009-161.htm" );
	script_tag( name: "impact", value: "Successful exploits may allow attackers to execute arbitrary code in
  the context of applications using the vulnerable PHP functions. This
  may result in a compromise of the underlying system. Failed attempts
  may lead to a denial-of-service condition." );
	script_tag( name: "affected", value: "Versions prior to PHP 4.4.9 and PHP 5.2.8 are vulnerable." );
	script_tag( name: "solution", value: "Updates are available. Please see the references for more information." );
	script_tag( name: "summary", value: "PHP is prone to multiple buffer-overflow vulnerabilities." );
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
if( IsMatchRegexp( vers, "^4\\.4" ) ){
	if(version_is_less( version: vers, test_version: "4.4.9" )){
		vuln = TRUE;
		fix = "4.4.9";
	}
}
else {
	if(IsMatchRegexp( vers, "^5\\.2" )){
		if(version_is_less( version: vers, test_version: "5.2.8" )){
			vuln = TRUE;
			fix = "5.2.8";
		}
	}
}
if(vuln){
	report = report_fixed_ver( installed_version: vers, fixed_version: fix );
	security_message( data: report, port: port );
	exit( 0 );
}
exit( 99 );

