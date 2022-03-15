CPE = "cpe:/a:php:php";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.100146" );
	script_version( "2021-04-13T14:13:08+0000" );
	script_tag( name: "last_modification", value: "2021-04-13 14:13:08 +0000 (Tue, 13 Apr 2021)" );
	script_tag( name: "creation_date", value: "2009-04-16 19:20:22 +0200 (Thu, 16 Apr 2009)" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:P" );
	script_bugtraq_id( 33927 );
	script_cve_id( "CVE-2009-1271" );
	script_name( "PHP 5.2.8 and Prior Versions Multiple Vulnerabilities" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2009 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "secpod_php_smb_login_detect.sc", "gb_php_ssh_login_detect.sc", "gb_php_http_detect.sc" );
	script_mandatory_keys( "php/detected" );
	script_xref( name: "URL", value: "http://www.securityfocus.com/bid/33927" );
	script_tag( name: "impact", value: "Successful exploits could allow an attacker to cause a denial-of-service
  condition. An unspecified issue with an unknown impact was also reported." );
	script_tag( name: "affected", value: "These issues affect PHP 5.2.8 and prior versions." );
	script_tag( name: "solution", value: "The vendor has released PHP 5.2.9 to address these issues." );
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
if(version_is_less( version: vers, test_version: "5.2.9" )){
	report = report_fixed_ver( installed_version: vers, fixed_version: "5.2.9" );
	security_message( data: report, port: port );
	exit( 0 );
}
exit( 99 );

