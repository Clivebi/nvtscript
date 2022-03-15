CPE = "cpe:/a:php:php";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.100631" );
	script_version( "2021-04-13T14:13:08+0000" );
	script_tag( name: "last_modification", value: "2021-04-13 14:13:08 +0000 (Tue, 13 Apr 2021)" );
	script_tag( name: "creation_date", value: "2010-05-10 13:21:57 +0200 (Mon, 10 May 2010)" );
	script_bugtraq_id( 40013 );
	script_cve_id( "CVE-2010-1868" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_name( "PHP 'sqlite_single_query()' and 'sqlite_array_query()' Arbitrary Code Execution Vulnerabilities" );
	script_category( ACT_GATHER_INFO );
	script_family( "Web application abuses" );
	script_copyright( "Copyright (C) 2010 Greenbone Networks GmbH" );
	script_dependencies( "secpod_php_smb_login_detect.sc", "gb_php_ssh_login_detect.sc", "gb_php_http_detect.sc" );
	script_mandatory_keys( "php/detected" );
	script_xref( name: "URL", value: "http://www.securityfocus.com/bid/40013" );
	script_xref( name: "URL", value: "http://php-security.org/2010/05/07/mops-2010-012-php-sqlite_single_query-uninitialized-memory-usage-vulnerability/index.html" );
	script_xref( name: "URL", value: "http://php-security.org/2010/05/07/mops-2010-013-php-sqlite_array_query-uninitialized-memory-usage-vulnerability/index.html" );
	script_xref( name: "URL", value: "http://php-security.org/2010/05/07/mops-submission-03-sqlite_single_query-sqlite_array_query-uninitialized-memory-usage/index.html" );
	script_tag( name: "impact", value: "Attackers can exploit these issues to run arbitrary code within the
  context of the PHP process. This may allow them to bypass intended
  security restrictions or gain elevated privileges." );
	script_tag( name: "affected", value: "PHP 5.3.0 through 5.3.2, PHP 5.2.0 through 5.2.13 are vulnerable" );
	script_tag( name: "solution", value: "Updates are available. Please see the references for more information." );
	script_tag( name: "summary", value: "PHP is prone to multiple vulnerabilities that may allow
  attackers to execute arbitrary code." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "remote_banner_unreliable" );
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
if(version_in_range( version: vers, test_version: "5.3", test_version2: "5.3.2" ) || version_in_range( version: vers, test_version: "5.2", test_version2: "5.2.13" )){
	report = report_fixed_ver( installed_version: vers, fixed_version: "5.3.3/5.2.14" );
	security_message( data: report, port: port );
	exit( 0 );
}
exit( 99 );

