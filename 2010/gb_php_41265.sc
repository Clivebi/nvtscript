CPE = "cpe:/a:php:php";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.100695" );
	script_version( "2021-04-13T14:13:08+0000" );
	script_tag( name: "last_modification", value: "2021-04-13 14:13:08 +0000 (Tue, 13 Apr 2021)" );
	script_tag( name: "creation_date", value: "2010-07-05 12:40:56 +0200 (Mon, 05 Jul 2010)" );
	script_bugtraq_id( 41265 );
	script_cve_id( "CVE-2010-2484" );
	script_name( "PHP 'strrchr()' Function Information Disclosure Vulnerability" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:N/A:N" );
	script_category( ACT_GATHER_INFO );
	script_family( "Web application abuses" );
	script_copyright( "Copyright (C) 2010 Greenbone Networks GmbH" );
	script_dependencies( "secpod_php_smb_login_detect.sc", "gb_php_ssh_login_detect.sc", "gb_php_http_detect.sc" );
	script_mandatory_keys( "php/detected" );
	script_xref( name: "URL", value: "http://www.securityfocus.com/bid/41265" );
	script_xref( name: "URL", value: "http://permalink.gmane.org/gmane.comp.security.oss.general/3109" );
	script_tag( name: "impact", value: "Attackers can exploit this issue to obtain sensitive information that
  may lead to further attacks." );
	script_tag( name: "affected", value: "PHP 5 through 5.3.2 are vulnerable." );
	script_tag( name: "solution", value: "Updates are available. Please see the references for details." );
	script_tag( name: "summary", value: "PHP is prone to an information-disclosure vulnerability." );
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
if(version_in_range( version: vers, test_version: "5", test_version2: "5.3.2" )){
	report = report_fixed_ver( installed_version: vers, fixed_version: "5.3.3" );
	security_message( data: report, port: port );
	exit( 0 );
}
exit( 99 );

