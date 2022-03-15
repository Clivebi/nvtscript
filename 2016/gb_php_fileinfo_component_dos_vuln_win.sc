CPE = "cpe:/a:php:php";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.808668" );
	script_version( "2021-04-13T14:13:08+0000" );
	script_cve_id( "CVE-2014-0236" );
	script_bugtraq_id( 90957 );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:P" );
	script_tag( name: "last_modification", value: "2021-04-13 14:13:08 +0000 (Tue, 13 Apr 2021)" );
	script_tag( name: "creation_date", value: "2016-08-31 14:22:58 +0530 (Wed, 31 Aug 2016)" );
	script_name( "PHP Fileinfo Component Denial of Service Vulnerability (Windows)" );
	script_tag( name: "summary", value: "PHP is prone to a denial of service (DoS) vulnerability." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "The flaw is due an improper validation of input
  to zero root_storage value in a CDF file." );
	script_tag( name: "impact", value: "Successfully exploiting this issue allow
  remote attackers to cause a denial of service." );
	script_tag( name: "affected", value: "PHP versions prior to 5.6.0 on Windows" );
	script_tag( name: "solution", value: "Update to PHP version 5.6.0" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_xref( name: "URL", value: "http://www.php.net/ChangeLog-5.php" );
	script_copyright( "Copyright (C) 2016 Greenbone Networks GmbH" );
	script_category( ACT_GATHER_INFO );
	script_family( "Web application abuses" );
	script_dependencies( "secpod_php_smb_login_detect.sc", "gb_php_http_detect.sc", "os_detection.sc" );
	script_mandatory_keys( "php/detected", "Host/runs_windows" );
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
if(version_is_less( version: phpVer, test_version: "5.6.0" )){
	report = report_fixed_ver( installed_version: phpVer, fixed_version: "5.6.0" );
	security_message( data: report, port: phpPort );
	exit( 0 );
}
exit( 99 );

