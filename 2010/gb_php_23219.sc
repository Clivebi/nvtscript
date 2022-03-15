CPE = "cpe:/a:php:php";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.100595" );
	script_version( "2021-04-13T14:13:08+0000" );
	script_tag( name: "last_modification", value: "2021-04-13 14:13:08 +0000 (Tue, 13 Apr 2021)" );
	script_tag( name: "creation_date", value: "2010-04-21 13:10:07 +0200 (Wed, 21 Apr 2010)" );
	script_bugtraq_id( 23219 );
	script_cve_id( "CVE-2007-1884" );
	script_name( "PHP Printf() Function 64bit Casting Multiple Format String Vulnerabilities" );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_category( ACT_GATHER_INFO );
	script_family( "Web application abuses" );
	script_copyright( "Copyright (C) 2010 Greenbone Networks GmbH" );
	script_dependencies( "secpod_php_smb_login_detect.sc", "gb_php_ssh_login_detect.sc", "gb_php_http_detect.sc" );
	script_mandatory_keys( "php/detected" );
	script_xref( name: "URL", value: "http://www.securityfocus.com/bid/23219" );
	script_xref( name: "URL", value: "http://www8.itrc.hp.com/service/cki/docDisplay.do?docId=c01056506" );
	script_xref( name: "URL", value: "http://www.php-security.org/MOPB/MOPB-38-2007.html" );
	script_xref( name: "URL", value: "http://www.php.net/releases/4_4_5.php" );
	script_xref( name: "URL", value: "http://www.php.net/releases/5_2_1.php" );
	script_tag( name: "impact", value: "Attackers may be able to exploit these issues to execute arbitrary
  code in the context of the webserver process or to cause denial-of-service conditions." );
	script_tag( name: "affected", value: "These issues affect PHP versions prior to 4.4.5 and 5.2.1 running on
  64-bit computers." );
	script_tag( name: "solution", value: "The vendor released versions 5.2.1 and 4.4.5 to address these issues.
  Please see the references for more information." );
	script_tag( name: "summary", value: "PHP is prone to multiple format-string vulnerabilities due to
  a design error when casting 64-bit variables to 32 bits." );
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

