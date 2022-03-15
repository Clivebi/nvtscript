CPE = "cpe:/a:php:php";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.805412" );
	script_version( "2021-04-13T14:13:08+0000" );
	script_cve_id( "CVE-2014-9425", "CVE-2014-9709" );
	script_bugtraq_id( 71800, 73306 );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2021-04-13 14:13:08 +0000 (Tue, 13 Apr 2021)" );
	script_tag( name: "creation_date", value: "2015-01-07 11:41:02 +0530 (Wed, 07 Jan 2015)" );
	script_name( "PHP Multiple Double Free Vulnerabilities - Jan15" );
	script_tag( name: "summary", value: "PHP is prone to a denial of service (DoS) vulnerability." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "Multiple flaws are due to:

  - Double free error in the 'zend_ts_hash_graceful_destroy' function in
  'zend_ts_hash.c script in the Zend Engine in PHP.

  - flaw in the 'GetCode_' function in 'gd_gif_in.c' script  in GD Graphics
  Library (LibGD)." );
	script_tag( name: "impact", value: "Successful exploitation will allow
  remote attackers to cause a denial of service or possibly have unspecified
  other impact." );
	script_tag( name: "affected", value: "PHP versions through 5.5.20
  and 5.6.x through 5.6.4" );
	script_tag( name: "solution", value: "Update to PHP version 5.5.21
  or 5.6.5 or later." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "remote_banner_unreliable" );
	script_xref( name: "URL", value: "http://securitytracker.com/id/1031479" );
	script_xref( name: "URL", value: "https://bugs.php.net/bug.php?id=68676" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2015 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "secpod_php_smb_login_detect.sc", "gb_php_ssh_login_detect.sc", "gb_php_http_detect.sc" );
	script_mandatory_keys( "php/detected" );
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
if(version_is_less_equal( version: phpVer, test_version: "5.5.20" ) || version_in_range( version: phpVer, test_version: "5.6.0", test_version2: "5.6.4" )){
	report = report_fixed_ver( installed_version: phpVer, fixed_version: "5.5.21/5.6.5" );
	security_message( data: report, port: phpPort );
	exit( 0 );
}
exit( 99 );

