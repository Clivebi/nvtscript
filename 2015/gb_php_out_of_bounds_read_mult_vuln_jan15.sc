CPE = "cpe:/a:php:php";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.805414" );
	script_version( "2021-04-13T14:13:08+0000" );
	script_cve_id( "CVE-2014-9427" );
	script_bugtraq_id( 71833 );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2021-04-13 14:13:08 +0000 (Tue, 13 Apr 2021)" );
	script_tag( name: "creation_date", value: "2015-01-07 13:04:22 +0530 (Wed, 07 Jan 2015)" );
	script_name( "PHP Out of Bounds Read Multiple Vulnerabilities - Jan15" );
	script_tag( name: "summary", value: "PHP is prone to a denial of service (DoS) vulnerability." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "The flaw is due to an out-of-bounds
  read error in sapi/cgi/cgi_main.c in the CGI component in PHP." );
	script_tag( name: "impact", value: "Successful exploitation will allow
  remote attackers to obtain sensitive information and trigger unexpected
  code execution ." );
	script_tag( name: "affected", value: "PHP versions through 5.4.36,
  5.5.x through 5.5.20, and 5.6.x through 5.6.4" );
	script_tag( name: "solution", value: "Update to PHP version 5.4.37
  or 5.5.21 or 5.6.5 or later." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "remote_banner_unreliable" );
	script_xref( name: "URL", value: "https://bugs.php.net/bug.php?id=68618" );
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
if(version_is_less_equal( version: phpVer, test_version: "5.4.36" ) || version_in_range( version: phpVer, test_version: "5.5.0", test_version2: "5.5.20" ) || version_in_range( version: phpVer, test_version: "5.6.0", test_version2: "5.6.4" )){
	report = report_fixed_ver( installed_version: phpVer, fixed_version: "5.4.37/5.5.21/5.6.5" );
	security_message( data: report, port: phpPort );
	exit( 0 );
}
exit( 99 );

