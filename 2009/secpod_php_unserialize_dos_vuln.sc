CPE = "cpe:/a:php:php";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.900993" );
	script_version( "2021-09-01T12:57:33+0000" );
	script_tag( name: "last_modification", value: "2021-09-01 12:57:33 +0000 (Wed, 01 Sep 2021)" );
	script_tag( name: "creation_date", value: "2009-12-31 08:44:14 +0100 (Thu, 31 Dec 2009)" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:P" );
	script_cve_id( "CVE-2009-4418" );
	script_name( "PHP 'unserialize()' Function Denial of Service Vulnerability" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2009 Greenbone Networks GmbH" );
	script_family( "Denial of Service" );
	script_dependencies( "secpod_php_smb_login_detect.sc", "gb_php_ssh_login_detect.sc", "gb_php_http_detect.sc" );
	script_mandatory_keys( "php/detected" );
	script_xref( name: "URL", value: "http://www.security-database.com/detail.php?alert=CVE-2009-4418" );
	script_xref( name: "URL", value: "http://www.suspekt.org/downloads/POC2009-ShockingNewsInPHPExploitation.pdf" );
	script_tag( name: "impact", value: "Successful exploitation could allow attackers to execute arbitrary PHP
  code and cause denial of service." );
	script_tag( name: "affected", value: "PHP 5.3.0 and prior on all running platform." );
	script_tag( name: "insight", value: "An error in 'unserialize()' function while processing malformed user supplied
  data containing a long serialized string passed via the '__wakeup()' or
  '__destruct()' methods." );
	script_tag( name: "solution", value: "No known solution was made available for at least one year
  since the disclosure of this vulnerability. Likely none will be provided anymore.
  General solution options are to upgrade to a newer release, disable respective
  features, remove the product or replace the product by another one." );
	script_tag( name: "summary", value: "PHP is prone to aDenial of Service vulnerability." );
	script_tag( name: "solution_type", value: "WillNotFix" );
	script_tag( name: "qod_type", value: "remote_banner_unreliable" );
	exit( 0 );
}
require("version_func.inc.sc");
require("host_details.inc.sc");
if(isnull( phpPort = get_app_port( cpe: CPE ) )){
	exit( 0 );
}
if(!phpVer = get_app_version( cpe: CPE, port: phpPort )){
	exit( 0 );
}
if(version_is_less_equal( version: phpVer, test_version: "5.3.0" )){
	report = report_fixed_ver( installed_version: phpVer, fixed_version: "None" );
	security_message( data: report, port: phpPort );
	exit( 0 );
}
exit( 99 );

