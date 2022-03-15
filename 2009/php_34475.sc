CPE = "cpe:/a:php:php";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.100145" );
	script_version( "2021-04-13T14:13:08+0000" );
	script_tag( name: "last_modification", value: "2021-04-13 14:13:08 +0000 (Tue, 13 Apr 2021)" );
	script_tag( name: "creation_date", value: "2009-04-16 19:20:22 +0200 (Thu, 16 Apr 2009)" );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:P/A:N" );
	script_bugtraq_id( 34475 );
	script_name( "PHP cURL 'safe_mode' and 'open_basedir' Restriction-Bypass Vulnerability" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2009 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "secpod_php_smb_login_detect.sc", "gb_php_ssh_login_detect.sc", "gb_php_http_detect.sc" );
	script_mandatory_keys( "php/detected" );
	script_xref( name: "URL", value: "http://www.securityfocus.com/bid/34475" );
	script_tag( name: "impact", value: "Successful exploits could allow an attacker to
  access files in unauthorized locations." );
	script_tag( name: "affected", value: "PHP 5.2.9 is vulnerable. Other versions may also be affected." );
	script_tag( name: "insight", value: "This vulnerability would be an issue in shared-hosting
  configurations where multiple users can create and execute
  arbitrary PHP script code, with the safe_mode and open_basedir
  restrictions assumed to isolate the users from each other." );
	script_tag( name: "summary", value: "PHP is prone to a safe_mode and open_basedir restriction-bypass
  vulnerability." );
	script_tag( name: "solution", value: "No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one." );
	script_tag( name: "qod_type", value: "remote_banner_unreliable" );
	script_tag( name: "solution_type", value: "WillNotFix" );
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
if(version_is_equal( version: vers, test_version: "5.2.9" )){
	report = report_fixed_ver( installed_version: vers, fixed_version: "N/A" );
	security_message( data: report, port: port );
	exit( 0 );
}
exit( 99 );

