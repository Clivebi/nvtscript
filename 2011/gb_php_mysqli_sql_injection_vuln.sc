CPE = "cpe:/a:php:php";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.801584" );
	script_version( "2021-04-13T14:13:08+0000" );
	script_tag( name: "last_modification", value: "2021-04-13 14:13:08 +0000 (Tue, 13 Apr 2021)" );
	script_tag( name: "creation_date", value: "2011-02-01 16:46:08 +0100 (Tue, 01 Feb 2011)" );
	script_cve_id( "CVE-2010-4700" );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_name( "PHP 'set_magic_quotes_runtime()' SQL Injection Vulnerability" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2011 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "secpod_php_smb_login_detect.sc", "gb_php_ssh_login_detect.sc", "gb_php_http_detect.sc" );
	script_mandatory_keys( "php/detected" );
	script_xref( name: "URL", value: "http://bugs.php.net/52221" );
	script_xref( name: "URL", value: "http://www.php.net/ChangeLog-5.php" );
	script_tag( name: "impact", value: "Successful exploitation could allow local attackers to conduct SQL injection
  attacks via crafted input that had been properly handled in earlier versions." );
	script_tag( name: "affected", value: "PHP version 5.3.2 to 5.3.3." );
	script_tag( name: "insight", value: "The flaw is due to an error in 'set_magic_quotes_runtime()' when the
  MySQLi extension is used, which fails to properly interact with use of the
  'mysqli_fetch_assoc()' function." );
	script_tag( name: "solution", value: "Update to PHP 5.3.5 or later." );
	script_tag( name: "summary", value: "PHP is prone to an SQL injection vulnerability." );
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
if(version_in_range( version: vers, test_version: "5.3.2", test_version2: "5.3.3" )){
	report = report_fixed_ver( installed_version: vers, fixed_version: "5.3.5" );
	security_message( data: report, port: port );
	exit( 0 );
}
exit( 99 );

