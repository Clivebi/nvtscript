CPE = "cpe:/a:php:php";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.900185" );
	script_version( "2021-08-18T10:41:57+0000" );
	script_tag( name: "last_modification", value: "2021-08-18 10:41:57 +0000 (Wed, 18 Aug 2021)" );
	script_tag( name: "creation_date", value: "2008-12-31 15:14:17 +0100 (Wed, 31 Dec 2008)" );
	script_tag( name: "cvss_base", value: "10.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:C/A:C" );
	script_cve_id( "CVE-2008-5557" );
	script_bugtraq_id( 32948 );
	script_name( "PHP Heap-based buffer overflow in 'mbstring' extension" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2008 Greenbone Networks GmbH" );
	script_family( "Buffer overflow" );
	script_dependencies( "secpod_php_smb_login_detect.sc", "gb_php_ssh_login_detect.sc", "gb_php_http_detect.sc" );
	script_mandatory_keys( "php/detected" );
	script_xref( name: "URL", value: "http://bugs.php.net/bug.php?id=45722" );
	script_xref( name: "URL", value: "http://archives.neohapsis.com/archives/fulldisclosure/2008-12/0477.html" );
	script_tag( name: "impact", value: "Successful exploitation could allow attackers to execute arbitrary code via
  a crafted string containing an HTML entity." );
	script_tag( name: "affected", value: "PHP version 4.3.0 to 5.2.6 on all running platform." );
	script_tag( name: "insight", value: "The flaw is due to error in mbfilter_htmlent.c file in the mbstring
  extension. These can be exploited via mb_convert_encoding, mb_check_encoding,
  mb_convert_variables, and mb_parse_str functions." );
	script_tag( name: "solution", value: "Update to version 5.2.7 or later." );
	script_tag( name: "summary", value: "PHP is prone to a buffer overflow vulnerability." );
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
if(version_in_range( version: phpVer, test_version: "4.3.0", test_version2: "5.2.6" )){
	report = report_fixed_ver( installed_version: phpVer, fixed_version: "5.2.7" );
	security_message( data: report, port: phpPort );
	exit( 0 );
}
exit( 99 );

