CPE = "cpe:/a:php:php";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.800334" );
	script_version( "2021-04-13T14:13:08+0000" );
	script_tag( name: "last_modification", value: "2021-04-13 14:13:08 +0000 (Tue, 13 Apr 2021)" );
	script_tag( name: "creation_date", value: "2009-01-08 07:43:30 +0100 (Thu, 08 Jan 2009)" );
	script_tag( name: "cvss_base", value: "2.6" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:H/Au:N/C:N/I:P/A:N" );
	script_cve_id( "CVE-2008-5814" );
	script_name( "PHP display_errors XSS Vulnerability" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2009 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "secpod_php_smb_login_detect.sc", "gb_php_ssh_login_detect.sc", "gb_php_http_detect.sc" );
	script_mandatory_keys( "php/detected" );
	script_xref( name: "URL", value: "http://jvn.jp/en/jp/JVN50327700/index.html" );
	script_xref( name: "URL", value: "http://jvndb.jvn.jp/en/contents/2008/JVNDB-2008-000084.html" );
	script_tag( name: "impact", value: "Successful exploitation could allow attackers to inject arbitrary web script
  or HTML via unspecified vectors and conduct Cross-Site Scripting attacks." );
	script_tag( name: "affected", value: "PHP version 5.2.7 and prior on all running platform." );
	script_tag( name: "insight", value: "The flaw is due to improper handling of certain inputs when
  display_errors settings is enabled." );
	script_tag( name: "solution", value: "Update to version 5.2.8 or later." );
	script_tag( name: "summary", value: "PHP is prone to a cross-site scripting (XSS)
  vulnerability." );
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
if(version_is_less_equal( version: phpVer, test_version: "5.2.7" )){
	report = report_fixed_ver( installed_version: phpVer, fixed_version: "5.2.8" );
	security_message( data: report, port: phpPort );
	exit( 0 );
}
exit( 99 );

