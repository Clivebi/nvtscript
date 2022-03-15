CPE = "cpe:/a:php:php";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.900184" );
	script_version( "2021-08-18T10:41:57+0000" );
	script_tag( name: "last_modification", value: "2021-08-18 10:41:57 +0000 (Wed, 18 Aug 2021)" );
	script_tag( name: "creation_date", value: "2008-12-26 14:23:17 +0100 (Fri, 26 Dec 2008)" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_cve_id( "CVE-2008-5624", "CVE-2008-5625", "CVE-2008-5658" );
	script_bugtraq_id( 32383, 32625, 32688 );
	script_name( "PHP Security Bypass and File Writing Vulnerability - Dec08" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2008 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "secpod_php_smb_login_detect.sc", "gb_php_ssh_login_detect.sc", "gb_php_http_detect.sc" );
	script_mandatory_keys( "php/detected" );
	script_xref( name: "URL", value: "http://www.php.net/ChangeLog-5.php#5.2.7" );
	script_xref( name: "URL", value: "http://www.php.net/archive/2008.php#id2008-12-07-1" );
	script_xref( name: "URL", value: "http://www.securityfocus.com/archive/1/archive/1/498985/100/0/threaded" );
	script_tag( name: "impact", value: "Successful exploitation could allow remote attackers to write arbitrary file,
  bypass security restrictions and cause directory traversal attacks." );
	script_tag( name: "affected", value: "PHP versions prior to 5.2.7." );
	script_tag( name: "insight", value: "The flaw is due to:

  - An error in initialization of 'page_uid' and 'page_gid' global variables
  for use by the SAPI 'php_getuid' function, which bypass the safe_mode
  restrictions.

  - When 'safe_mode' is enabled through a 'php_admin_flag' setting in
  'httpd.conf' file, which does not enforce the 'error_log', 'safe_mode
  restrictions.

  - In 'ZipArchive::extractTo' function which allows attacker to write files
  via a ZIP file." );
	script_tag( name: "solution", value: "Update to version 5.2.7 or later." );
	script_tag( name: "summary", value: "PHP is prone to a security bypass and file writing vulnerability." );
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
if(version_in_range( version: phpVer, test_version: "5.0", test_version2: "5.2.6" )){
	report = report_fixed_ver( installed_version: phpVer, fixed_version: "5.2.7" );
	security_message( data: report, port: phpPort );
	exit( 0 );
}
exit( 99 );

