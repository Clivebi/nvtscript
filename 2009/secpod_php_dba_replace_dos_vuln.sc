CPE = "cpe:/a:php:php";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.900925" );
	script_version( "2021-09-01T12:57:33+0000" );
	script_tag( name: "last_modification", value: "2021-09-01 12:57:33 +0000 (Wed, 01 Sep 2021)" );
	script_tag( name: "creation_date", value: "2009-08-27 13:43:20 +0200 (Thu, 27 Aug 2009)" );
	script_tag( name: "cvss_base", value: "6.4" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:P/A:P" );
	script_cve_id( "CVE-2008-7068" );
	script_bugtraq_id( 33498 );
	script_name( "PHP dba_replace Denial of Service Vulnerability" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2009 Greenbone Networks GmbH" );
	script_family( "Denial of Service" );
	script_dependencies( "secpod_php_smb_login_detect.sc", "gb_php_ssh_login_detect.sc", "gb_php_http_detect.sc" );
	script_mandatory_keys( "php/detected" );
	script_xref( name: "URL", value: "http://xforce.iss.net/xforce/xfdb/47316" );
	script_xref( name: "URL", value: "http://www.securityfocus.com/archive/1/archive/1/498746/100/0/threaded" );
	script_tag( name: "impact", value: "Successful exploitation could allow attackers to execute arbitrary code
  corrupt files and cause denial of service." );
	script_tag( name: "affected", value: "PHP 4.x and 5.2.6 on all running platform." );
	script_tag( name: "insight", value: "An error occurs in 'dba_replace()' function while processing malformed
  user supplied data containing a key with the NULL byte." );
	script_tag( name: "solution", value: "Update to version 5.2.7 or later." );
	script_tag( name: "summary", value: "PHP is prone to a Denial of Service vulnerability." );
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
if(IsMatchRegexp( phpVer, "^4\\." ) || version_is_equal( version: phpVer, test_version: "5.2.6" )){
	report = report_fixed_ver( installed_version: phpVer, fixed_version: "5.2.7" );
	security_message( data: report, port: phpPort );
	exit( 0 );
}
exit( 99 );

