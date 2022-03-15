CPE = "cpe:/a:php:php";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.900186" );
	script_version( "2021-08-18T10:41:57+0000" );
	script_tag( name: "last_modification", value: "2021-08-18 10:41:57 +0000 (Wed, 18 Aug 2021)" );
	script_tag( name: "creation_date", value: "2008-12-31 15:14:17 +0100 (Wed, 31 Dec 2008)" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:N/A:N" );
	script_cve_id( "CVE-2008-5498" );
	script_bugtraq_id( 33002 );
	script_name( "PHP 'imageRotate()' Memory Information Disclosure Vulnerability" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2008 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "secpod_php_smb_login_detect.sc", "gb_php_ssh_login_detect.sc", "gb_php_http_detect.sc" );
	script_mandatory_keys( "php/detected" );
	script_xref( name: "URL", value: "http://securitytracker.com/alerts/2008/Dec/1021494.html" );
	script_xref( name: "URL", value: "http://downloads.securityfocus.com/vulnerabilities/exploits/33002.php" );
	script_xref( name: "URL", value: "http://downloads.securityfocus.com/vulnerabilities/exploits/33002-2.php" );
	script_tag( name: "impact", value: "Successful exploitation could let the attacker read the contents of arbitrary
  memory locations through a crafted value for an indexed image." );
	script_tag( name: "affected", value: "PHP version 5.x to 5.2.8 on all running platform." );
	script_tag( name: "insight", value: "The flaw is due to improper validation of bgd_color or clrBack
  argument in imageRotate function." );
	script_tag( name: "solution", value: "Update to PHP version 5.2.9 or later." );
	script_tag( name: "summary", value: "PHP is prone to a memory information disclosure vulnerability." );
	script_tag( name: "solution_type", value: "VendorFix" );
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
if(version_in_range( version: phpVer, test_version: "5.0", test_version2: "5.2.8" )){
	report = report_fixed_ver( installed_version: phpVer, fixed_version: "5.2.9" );
	security_message( data: report, port: phpPort );
	exit( 0 );
}
exit( 99 );

