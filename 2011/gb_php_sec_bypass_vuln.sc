CPE = "cpe:/a:php:php";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.801731" );
	script_version( "2021-04-13T14:13:08+0000" );
	script_tag( name: "last_modification", value: "2021-04-13 14:13:08 +0000 (Tue, 13 Apr 2021)" );
	script_tag( name: "creation_date", value: "2011-02-07 15:21:16 +0100 (Mon, 07 Feb 2011)" );
	script_cve_id( "CVE-2011-0752" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:P/A:N" );
	script_name( "PHP 'extract()' Function Security Bypass Vulnerability" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2011 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "secpod_php_smb_login_detect.sc", "gb_php_ssh_login_detect.sc", "gb_php_http_detect.sc" );
	script_mandatory_keys( "php/detected" );
	script_xref( name: "URL", value: "http://www.php.net/releases/5_2_15.php" );
	script_xref( name: "URL", value: "http://www.openwall.com/lists/oss-security/2010/12/13/4" );
	script_tag( name: "impact", value: "Successful exploitation could allows remote attackers to bypass intended
  access restrictions by modifying data structures that were not intended
  to depend on external input." );
	script_tag( name: "affected", value: "PHP version prior to 5.2.15." );
	script_tag( name: "insight", value: "The flaw is due to error in 'extract()' function, it does not prevent
  use of the 'EXTR_OVERWRITE' parameter to overwrite the GLOBALS superglobal array." );
	script_tag( name: "solution", value: "Update to PHP version 5.2.15 or later" );
	script_tag( name: "summary", value: "PHP is prone to a security bypass vulnerability." );
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
if(version_is_less( version: vers, test_version: "5.2.15" )){
	report = report_fixed_ver( installed_version: vers, fixed_version: "5.2.15" );
	security_message( data: report, port: port );
	exit( 0 );
}
exit( 99 );

