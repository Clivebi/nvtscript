CPE = "cpe:/a:php:php";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.103464" );
	script_bugtraq_id( 51806 );
	script_cve_id( "CVE-2012-0057" );
	script_tag( name: "cvss_base", value: "6.4" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:N" );
	script_version( "2021-04-13T14:13:08+0000" );
	script_name( "PHP Security Bypass Vulnerability" );
	script_tag( name: "last_modification", value: "2021-04-13 14:13:08 +0000 (Tue, 13 Apr 2021)" );
	script_tag( name: "creation_date", value: "2012-04-12 10:58:35 +0200 (Thu, 12 Apr 2012)" );
	script_category( ACT_GATHER_INFO );
	script_family( "Web application abuses" );
	script_copyright( "Copyright (C) 2012 Greenbone Networks GmbH" );
	script_dependencies( "secpod_php_smb_login_detect.sc", "gb_php_ssh_login_detect.sc", "gb_php_http_detect.sc" );
	script_mandatory_keys( "php/detected" );
	script_xref( name: "URL", value: "http://www.securityfocus.com/bid/51806" );
	script_xref( name: "URL", value: "https://bugs.php.net/bug.php?id=54446" );
	script_xref( name: "URL", value: "https://bugzilla.redhat.com/show_bug.cgi?id=782657" );
	script_xref( name: "URL", value: "http://www.php.net/ChangeLog-5.php" );
	script_tag( name: "impact", value: "Remote attackers can exploit this issue to bypass certain security
  restrictions and create arbitrary files in the context of the application." );
	script_tag( name: "affected", value: "Versions prior to PHP 5.3.9 are vulnerable." );
	script_tag( name: "solution", value: "Updates are available. Please see the references for more information." );
	script_tag( name: "summary", value: "PHP is prone to a security-bypass vulnerability." );
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
if(version_in_range( version: vers, test_version: "5.3", test_version2: "5.3.8" )){
	report = report_fixed_ver( installed_version: vers, fixed_version: "5.3.9" );
	security_message( data: report, port: port );
	exit( 0 );
}
exit( 99 );

