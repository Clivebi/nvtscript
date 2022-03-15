CPE = "cpe:/a:php:php";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.807506" );
	script_version( "2021-08-10T15:24:26+0000" );
	script_cve_id( "CVE-2015-8617", "CVE-2015-8616" );
	script_bugtraq_id( 79655, 79672 );
	script_tag( name: "cvss_base", value: "10.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:C/A:C" );
	script_tag( name: "last_modification", value: "2021-08-10 15:24:26 +0000 (Tue, 10 Aug 2021)" );
	script_tag( name: "creation_date", value: "2016-03-01 16:56:54 +0530 (Tue, 01 Mar 2016)" );
	script_name( "PHP Multiple Vulnerabilities - 02 - Mar16 (Linux)" );
	script_tag( name: "summary", value: "PHP is prone to multiple vulnerabilities." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "Multiple flaws are due to:

  - An use-after-free vulnerability in the 'Collator::sortWithSortKeys' function
    in 'ext/intl/collator/collator_sort.c' script.

  - A format string vulnerability in the 'zend_throw_or_error' function in
    'Zend/zend_execute_API.c' script." );
	script_tag( name: "impact", value: "Successfully exploiting this issue allow
  remote attackers to execute arbitrary code within the context of the affected
  application and to crash the affected application." );
	script_tag( name: "affected", value: "PHP version 7.0.0 on Linux" );
	script_tag( name: "solution", value: "Update to PHP version 7.0.1 or later." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "remote_banner_unreliable" );
	script_xref( name: "URL", value: "http://php.net/ChangeLog-7.php" );
	script_xref( name: "URL", value: "https://bugs.php.net/bug.php?id=71105" );
	script_copyright( "Copyright (C) 2016 Greenbone Networks GmbH" );
	script_category( ACT_GATHER_INFO );
	script_family( "Web application abuses" );
	script_dependencies( "gb_php_ssh_login_detect.sc", "gb_php_http_detect.sc", "os_detection.sc" );
	script_mandatory_keys( "php/detected", "Host/runs_unixoide" );
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
if(version_is_equal( version: vers, test_version: "7.0.0" )){
	report = report_fixed_ver( installed_version: vers, fixed_version: "7.0.0" );
	security_message( data: report, port: port );
	exit( 0 );
}
exit( 99 );

