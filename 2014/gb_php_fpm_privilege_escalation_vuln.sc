CPE = "cpe:/a:php:php";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.804290" );
	script_version( "2021-04-13T14:13:08+0000" );
	script_cve_id( "CVE-2014-0185" );
	script_bugtraq_id( 67118 );
	script_tag( name: "cvss_base", value: "7.2" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:L/Au:N/C:C/I:C/A:C" );
	script_tag( name: "last_modification", value: "2021-04-13 14:13:08 +0000 (Tue, 13 Apr 2021)" );
	script_tag( name: "creation_date", value: "2014-05-08 14:42:30 +0530 (Thu, 08 May 2014)" );
	script_name( "PHP 'FastCGI Process Manager' Privilege Escalation Vulnerability" );
	script_tag( name: "summary", value: "PHP is prone to a privilege escalation vulnerability." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "The flaw is due to error in 'sapi/fpm/fpm/fpm_unix.c' within FastCGI Process
  Manager that sets insecure permissions for a unix socket." );
	script_tag( name: "impact", value: "Successful exploitation will allow remote attackers to gain access to the
  socket and gain elevated privileges." );
	script_tag( name: "affected", value: "PHP versions 5.4.x before 5.4.28 and 5.5.x before 5.5.12." );
	script_tag( name: "solution", value: "Update to PHP version 5.4.28 or 5.5.12 or later." );
	script_xref( name: "URL", value: "http://seclists.org/oss-sec/2014/q2/192" );
	script_xref( name: "URL", value: "http://www.php.net/archive/2014.php#id2014-05-01-1" );
	script_xref( name: "URL", value: "http://www.openwall.com/lists/oss-security/2014/04/29/5" );
	script_copyright( "Copyright (C) 2014 Greenbone Networks GmbH" );
	script_category( ACT_GATHER_INFO );
	script_family( "Web application abuses" );
	script_dependencies( "secpod_php_smb_login_detect.sc", "gb_php_ssh_login_detect.sc", "gb_php_http_detect.sc" );
	script_mandatory_keys( "php/detected" );
	script_tag( name: "qod_type", value: "remote_banner_unreliable" );
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
if(version_in_range( version: vers, test_version: "5.4.0", test_version2: "5.4.27" ) || version_in_range( version: vers, test_version: "5.5.0", test_version2: "5.5.11" )){
	report = report_fixed_ver( installed_version: vers, fixed_version: "5.4.28/5.5.12" );
	security_message( data: report, port: port );
	exit( 0 );
}
exit( 99 );

