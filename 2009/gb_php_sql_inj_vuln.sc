CPE = "cpe:/a:php:php";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.800333" );
	script_version( "2021-04-13T14:13:08+0000" );
	script_tag( name: "last_modification", value: "2021-04-13 14:13:08 +0000 (Tue, 13 Apr 2021)" );
	script_tag( name: "creation_date", value: "2009-01-08 07:43:30 +0100 (Thu, 08 Jan 2009)" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_cve_id( "CVE-2008-5844" );
	script_bugtraq_id( 32673 );
	script_name( "PHP FILTER_UNSAFE_RAW SQL Injection Vulnerability" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2009 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "secpod_php_smb_login_detect.sc", "gb_php_ssh_login_detect.sc", "gb_php_http_detect.sc" );
	script_mandatory_keys( "php/detected" );
	script_xref( name: "URL", value: "http://bugs.php.net/bug.php?id=42718" );
	script_xref( name: "URL", value: "http://www.php.net/archive/2008.php#id2008-12-08-1" );
	script_tag( name: "impact", value: "Successful exploitation could allow attackers to inject SQL code in the
  affected user application, and this may lead to other attacks also." );
	script_tag( name: "affected", value: "PHP version 5.2.7 on all running platform." );
	script_tag( name: "insight", value: "The flaw is due to improper field change in FILTER_UNSAFE_RAW. These
  can be exploited when magic_quotes_gpc settings is disabled." );
	script_tag( name: "solution", value: "Update to version 5.2.8 or later." );
	script_tag( name: "summary", value: "PHP is prone to an SQL Injection vulnerability." );
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
if(version_is_equal( version: phpVer, test_version: "5.2.7" )){
	report = report_fixed_ver( installed_version: phpVer, fixed_version: "5.2.8" );
	security_message( data: report, port: phpPort );
	exit( 0 );
}
exit( 99 );

