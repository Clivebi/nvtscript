CPE = "cpe:/a:php:php";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.804639" );
	script_version( "2021-04-13T14:13:08+0000" );
	script_cve_id( "CVE-2014-0237", "CVE-2014-0238" );
	script_bugtraq_id( 67759, 67765 );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:P" );
	script_tag( name: "last_modification", value: "2021-04-13 14:13:08 +0000 (Tue, 13 Apr 2021)" );
	script_tag( name: "creation_date", value: "2014-06-16 10:22:50 +0530 (Mon, 16 Jun 2014)" );
	script_name( "PHP CDF File Parsing Denial of Service Vulnerabilities - 01 - Jun14" );
	script_tag( name: "summary", value: "PHP is prone to multiple denial of service vulnerabilities." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "The flaw is due to

  - An error due to an infinite loop within the 'unpack_summary_info' function in
  src/cdf.c script.

  - An error within the 'cdf_read_property_info' function in src/cdf.c script." );
	script_tag( name: "impact", value: "Successful exploitation will allow remote attackers to conduct denial of
  service attacks." );
	script_tag( name: "affected", value: "PHP version 5.x before 5.4.29 and 5.5.x before 5.5.13" );
	script_tag( name: "solution", value: "Update to PHP version 5.4.29 or 5.5.13 or later." );
	script_xref( name: "URL", value: "http://www.php.net/ChangeLog-5.php" );
	script_xref( name: "URL", value: "http://secunia.com/advisories/58804" );
	script_xref( name: "URL", value: "https://www.hkcert.org/my_url/en/alert/14060401" );
	script_copyright( "Copyright (C) 2014 Greenbone Networks GmbH" );
	script_category( ACT_GATHER_INFO );
	script_family( "Web application abuses" );
	script_dependencies( "secpod_php_smb_login_detect.sc", "gb_php_ssh_login_detect.sc", "gb_php_http_detect.sc" );
	script_mandatory_keys( "php/detected" );
	script_tag( name: "qod_type", value: "remote_banner_unreliable" );
	script_tag( name: "solution_type", value: "VendorFix" );
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
if(version_in_range( version: vers, test_version: "5.5.0", test_version2: "5.5.12" ) || version_in_range( version: vers, test_version: "5.0.0", test_version2: "5.4.28" )){
	report = report_fixed_ver( installed_version: vers, fixed_version: "5.4.29/5.5.13" );
	security_message( data: report, port: port );
	exit( 0 );
}
exit( 99 );

