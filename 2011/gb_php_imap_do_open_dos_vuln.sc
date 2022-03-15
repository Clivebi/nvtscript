CPE = "cpe:/a:php:php";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.801583" );
	script_version( "2021-04-13T14:13:08+0000" );
	script_tag( name: "last_modification", value: "2021-04-13 14:13:08 +0000 (Tue, 13 Apr 2021)" );
	script_tag( name: "creation_date", value: "2011-01-31 05:37:34 +0100 (Mon, 31 Jan 2011)" );
	script_cve_id( "CVE-2010-4150" );
	script_bugtraq_id( 44980 );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:P" );
	script_name( "PHP 'ext/imap/php_imap.c' Use After Free Denial of Service Vulnerability" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2011 Greenbone Networks GmbH" );
	script_family( "Denial of Service" );
	script_dependencies( "secpod_php_smb_login_detect.sc", "gb_php_ssh_login_detect.sc", "gb_php_http_detect.sc" );
	script_mandatory_keys( "php/detected" );
	script_tag( name: "impact", value: "Successful exploitation could allow local attackers to crash the affected
  application, denying service to legitimate users." );
	script_tag( name: "affected", value: "PHP version 5.2 before 5.2.15 and 5.3 before 5.3.4" );
	script_tag( name: "insight", value: "The flaw is due to an erron in 'imap_do_open' function in the IMAP
  extension 'ext/imap/php_imap.c'." );
	script_tag( name: "solution", value: "Update to PHP 5.2.15 or 5.3.4" );
	script_tag( name: "summary", value: "PHP is prone to a denial of service vulnerability." );
	script_xref( name: "URL", value: "http://xforce.iss.net/xforce/xfdb/63390" );
	script_xref( name: "URL", value: "http://svn.php.net/viewvc?view=revision&revision=305032" );
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
if(version_in_range( version: vers, test_version: "5.2", test_version2: "5.2.14" ) || version_in_range( version: vers, test_version: "5.3", test_version2: "5.3.3" )){
	report = report_fixed_ver( installed_version: vers, fixed_version: "5.2.15/5.3.4" );
	security_message( data: report, port: port );
	exit( 0 );
}
exit( 99 );

