CPE = "cpe:/a:php:php";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.801123" );
	script_version( "2021-04-13T14:13:08+0000" );
	script_tag( name: "last_modification", value: "2021-04-13 14:13:08 +0000 (Tue, 13 Apr 2021)" );
	script_tag( name: "creation_date", value: "2009-10-23 16:18:41 +0200 (Fri, 23 Oct 2009)" );
	script_tag( name: "cvss_base", value: "9.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:C/I:C/A:C" );
	script_cve_id( "CVE-2009-3546" );
	script_bugtraq_id( 36712 );
	script_name( "PHP '_gdGetColors()' Buffer Overflow Vulnerability" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2009 Greenbone Networks GmbH" );
	script_family( "Buffer overflow" );
	script_dependencies( "secpod_php_smb_login_detect.sc", "gb_php_ssh_login_detect.sc", "gb_php_http_detect.sc" );
	script_mandatory_keys( "php/detected" );
	script_xref( name: "URL", value: "http://secunia.com/advisories/37080/" );
	script_xref( name: "URL", value: "http://www.vupen.com/english/advisories/2009/2930" );
	script_xref( name: "URL", value: "http://marc.info/?l=oss-security&m=125562113503923&w=2" );
	script_tag( name: "impact", value: "Successful exploitation could allow attackers to potentially compromise a
  vulnerable system." );
	script_tag( name: "affected", value: "PHP version 5.2.x to 5.2.11 and 5.3.0 on Linux." );
	script_tag( name: "insight", value: "The flaw is due to error in '_gdGetColors' function in gd_gd.c which fails to
  check certain colorsTotal structure member, whicn can be exploited to cause
  buffer overflow or buffer over-read attacks via a crafted GD file." );
	script_tag( name: "solution", value: "Update to version 5.2.12, 5.3.1 or later." );
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
if(version_is_equal( version: phpVer, test_version: "5.3.0" ) || version_in_range( version: phpVer, test_version: "5.2", test_version2: "5.2.11" )){
	report = report_fixed_ver( installed_version: phpVer, fixed_version: "5.2.12/5.3.1" );
	security_message( data: report, port: phpPort );
	exit( 0 );
}
exit( 99 );

