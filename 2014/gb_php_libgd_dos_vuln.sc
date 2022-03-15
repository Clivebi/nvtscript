CPE = "cpe:/a:php:php";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.804292" );
	script_version( "2021-04-13T14:13:08+0000" );
	script_cve_id( "CVE-2014-2497" );
	script_bugtraq_id( 66233 );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:N/A:P" );
	script_tag( name: "last_modification", value: "2021-04-13 14:13:08 +0000 (Tue, 13 Apr 2021)" );
	script_tag( name: "creation_date", value: "2014-05-09 14:18:22 +0530 (Fri, 09 May 2014)" );
	script_name( "PHP 'LibGD' Denial of Service Vulnerability" );
	script_tag( name: "summary", value: "PHP is prone to a denial of service (DoS) vulnerability." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "The flaw is due to a NULL pointer dereference error in 'gdImageCreateFromXpm'
  function within LibGD." );
	script_tag( name: "impact", value: "Successful exploitation will allow remote attackers to conduct denial of
  service attacks." );
	script_tag( name: "affected", value: "PHP version 5.x through 5.4.26 and probably other versions." );
	script_tag( name: "solution", value: "Update to PHP version 5.4.32 or 5.5.16 or 5.6.0 or later." );
	script_xref( name: "URL", value: "https://bugs.php.net/bug.php?id=66901" );
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
if(version_in_range( version: vers, test_version: "5.0.0", test_version2: "5.4.26" )){
	report = report_fixed_ver( installed_version: vers, fixed_version: "5.4.32/5.5.16/5.6.0" );
	security_message( data: report, port: port );
	exit( 0 );
}
exit( 99 );

