CPE = "cpe:/a:php:php";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.802591" );
	script_version( "2021-04-13T14:13:08+0000" );
	script_tag( name: "last_modification", value: "2021-04-13 14:13:08 +0000 (Tue, 13 Apr 2021)" );
	script_tag( name: "creation_date", value: "2012-02-10 11:24:19 +0530 (Fri, 10 Feb 2012)" );
	script_cve_id( "CVE-2012-0831" );
	script_bugtraq_id( 51954 );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_name( "PHP 'magic_quotes_gpc' Directive Security Bypass Vulnerability (Windows)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2012 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "secpod_php_smb_login_detect.sc", "gb_php_http_detect.sc", "os_detection.sc" );
	script_mandatory_keys( "php/detected", "Host/runs_windows" );
	script_tag( name: "impact", value: "Successful exploitation could allow remote attackers to gain sensitive
  information via a crafted request." );
	script_tag( name: "affected", value: "PHP Version 5.3.9 and prior on Windows." );
	script_tag( name: "insight", value: "The flaw is due to an error in importing  environment variables,
  it not properly performing a temporary change to the 'magic_quotes_gpc'
  directive during the importing of environment variables." );
	script_tag( name: "solution", value: "Update to PHP Version 5.3.10 or later." );
	script_tag( name: "summary", value: "PHP is prone to a security bypass vulnerability." );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "URL", value: "http://www.securityfocus.com/bid/51954/info" );
	script_xref( name: "URL", value: "http://svn.php.net/viewvc?view=revision&revision=323016" );
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
if(version_is_less( version: vers, test_version: "5.3.10" )){
	report = report_fixed_ver( installed_version: vers, fixed_version: "5.3.10" );
	security_message( data: report, port: port );
	exit( 0 );
}
exit( 99 );

