CPE = "cpe:/a:php:php";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.100603" );
	script_version( "2021-04-13T14:13:08+0000" );
	script_bugtraq_id( 22805 );
	script_cve_id( "CVE-2007-1380" );
	script_name( "PHP PHP_Binary Heap Information Leak Vulnerability" );
	script_tag( name: "last_modification", value: "2021-04-13 14:13:08 +0000 (Tue, 13 Apr 2021)" );
	script_tag( name: "creation_date", value: "2010-04-23 13:12:25 +0200 (Fri, 23 Apr 2010)" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:N/A:N" );
	script_category( ACT_GATHER_INFO );
	script_family( "Web application abuses" );
	script_copyright( "Copyright (C) 2010 Greenbone Networks GmbH" );
	script_dependencies( "secpod_php_smb_login_detect.sc", "gb_php_ssh_login_detect.sc", "gb_php_http_detect.sc" );
	script_mandatory_keys( "php/detected" );
	script_xref( name: "URL", value: "http://www.securityfocus.com/bid/22805" );
	script_xref( name: "URL", value: "http://www8.itrc.hp.com/service/cki/docDisplay.do?docId=c01056506" );
	script_xref( name: "URL", value: "http://lists.suse.com/archive/suse-security-announce/2007-May/0007.html" );
	script_tag( name: "impact", value: "A local attacker can exploit this issue to obtain sensitive information
  (such as heap offsets and canaries) that may aid in other attacks." );
	script_tag( name: "affected", value: "PHP4 versions prior to 4.4.5 and PHP5 versions prior to 5.2.1." );
	script_tag( name: "insight", value: "The vulnerability exists because of a missing boundary check in the
  extraction of variable names." );
	script_tag( name: "solution", value: "This issue was previously disclosed to the PHP development team. It
  has been fixed in the latest releases." );
	script_tag( name: "summary", value: "PHP 'php_binary' serialization handler is prone to a heap-
  information leak." );
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

