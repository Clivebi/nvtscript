CPE = "cpe:/a:php:php";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.902356" );
	script_version( "2021-09-01T07:45:06+0000" );
	script_tag( name: "last_modification", value: "2021-09-01 07:45:06 +0000 (Wed, 01 Sep 2021)" );
	script_tag( name: "creation_date", value: "2011-03-22 08:43:18 +0100 (Tue, 22 Mar 2011)" );
	script_cve_id( "CVE-2011-1148" );
	script_bugtraq_id( 46843 );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_name( "PHP 'substr_replace()' Use After Free Vulnerability" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2011 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "secpod_php_smb_login_detect.sc", "gb_php_ssh_login_detect.sc", "gb_php_http_detect.sc" );
	script_mandatory_keys( "php/detected" );
	script_xref( name: "URL", value: "http://bugs.php.net/bug.php?id=54238" );
	script_xref( name: "URL", value: "http://openwall.com/lists/oss-security/2011/03/13/3" );
	script_tag( name: "impact", value: "Successful exploitation could allow remote attackers to execute
  arbitrary code in the context of a web server. Failed attempts will likely
  result in denial-of-service conditions." );
	script_tag( name: "affected", value: "PHP version 5.3.6 and prior." );
	script_tag( name: "insight", value: "The flaw is due to passing the same variable multiple times to
  the 'substr_replace()' function, which makes the PHP to use the same pointer in
  three variables inside the function." );
	script_tag( name: "solution", value: "Update to PHP version 5.3.7 or later." );
	script_tag( name: "summary", value: "PHP is prone to a use after free vulnerability." );
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
if(version_is_less_equal( version: vers, test_version: "5.3.6" )){
	report = report_fixed_ver( installed_version: vers, fixed_version: "5.3.7" );
	security_message( data: report, port: port );
	exit( 0 );
}
exit( 99 );

