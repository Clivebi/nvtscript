CPE = "cpe:/a:php:php";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.100604" );
	script_version( "2021-04-13T14:13:08+0000" );
	script_tag( name: "last_modification", value: "2021-04-13 14:13:08 +0000 (Tue, 13 Apr 2021)" );
	script_tag( name: "creation_date", value: "2010-04-23 13:12:25 +0200 (Fri, 23 Apr 2010)" );
	script_bugtraq_id( 22833 );
	script_cve_id( "CVE-2007-1379", "CVE-2007-1378" );
	script_name( "PHP Ovrimos Extension Code Execution Vulnerability" );
	script_tag( name: "cvss_base", value: "5.1" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:H/Au:N/C:P/I:P/A:P" );
	script_category( ACT_GATHER_INFO );
	script_family( "Web application abuses" );
	script_copyright( "Copyright (C) 2010 Greenbone Networks GmbH" );
	script_dependencies( "secpod_php_smb_login_detect.sc", "gb_php_ssh_login_detect.sc", "gb_php_http_detect.sc" );
	script_mandatory_keys( "php/detected" );
	script_xref( name: "URL", value: "http://www.securityfocus.com/bid/22833" );
	script_xref( name: "URL", value: "http://www.php-security.org/MOPB/MOPB-13-2007.html" );
	script_tag( name: "impact", value: "Successful exploits may allow an attacker to execute arbitrary code in
  the context of the affected application. Failed exploits would likely crash PHP." );
	script_tag( name: "affected", value: "PHP versions prior to 4.4.5 or 5.2.1 with a compiled 'Ovrimos SQL Server
  Extension' are vulnerable to this issue." );
	script_tag( name: "insight", value: "For this vulnerability to occur, the non-maintained 'Ovrimos SQL
  Server Extension' must have been compiled into the targeted PHP implementation." );
	script_tag( name: "summary", value: "PHP is prone to a code-execution vulnerability due to a design error
  in a vulnerable extension." );
	script_tag( name: "solution", value: "Update to PHP version 4.4.5, 5.2.1 or later." );
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
	if(version_is_less( version: vers, test_version: "4.4.5" )){
		vuln = TRUE;
		fix = "4.4.5";
	}
}
else {
	if(IsMatchRegexp( vers, "^5\\.2" )){
		if(version_is_less( version: vers, test_version: "5.2.1" )){
			vuln = TRUE;
			fix = "5.2.1";
		}
	}
}
if(vuln){
	report = report_fixed_ver( installed_version: vers, fixed_version: fix );
	security_message( data: report, port: port );
	exit( 0 );
}
exit( 99 );

