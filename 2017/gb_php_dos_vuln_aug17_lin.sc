CPE = "cpe:/a:php:php";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.811409" );
	script_version( "2021-09-10T14:01:42+0000" );
	script_cve_id( "CVE-2017-11362" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2021-09-10 14:01:42 +0000 (Fri, 10 Sep 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-05-22 16:29:00 +0000 (Wed, 22 May 2019)" );
	script_tag( name: "creation_date", value: "2017-08-01 10:20:01 +0530 (Tue, 01 Aug 2017)" );
	script_name( "PHP Denial of Service Vulnerability - Aug17 (Linux)" );
	script_tag( name: "summary", value: "PHP is prone to a denial of service (DoS) vulnerability." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "The flaw exists due to
  'ext/intl/msgformat/msgformat_parse.c' script does not restrict the locale length." );
	script_tag( name: "impact", value: "Successfully exploiting this issue allow
  remote attackers to cause a denial of service (stack-based buffer overflow and
  application crash) or possibly have unspecified impact." );
	script_tag( name: "affected", value: "PHP versions 7.x before 7.0.21 and 7.1.x
  before 7.1.7" );
	script_tag( name: "solution", value: "Update to PHP version 7.0.21, or 7.1.7
  or later." );
	script_xref( name: "URL", value: "http://www.php.net/ChangeLog-7.php" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "remote_banner_unreliable" );
	script_copyright( "Copyright (C) 2017 Greenbone Networks GmbH" );
	script_category( ACT_GATHER_INFO );
	script_family( "Denial of Service" );
	script_dependencies( "gb_php_ssh_login_detect.sc", "gb_php_http_detect.sc", "os_detection.sc" );
	script_mandatory_keys( "php/detected", "Host/runs_unixoide" );
	exit( 0 );
}
require("version_func.inc.sc");
require("host_details.inc.sc");
if(isnull( phpport = get_app_port( cpe: CPE ) )){
	exit( 0 );
}
if(!vers = get_app_version( cpe: CPE, port: phpport )){
	exit( 0 );
}
if( IsMatchRegexp( vers, "^7\\.0" ) ){
	if(version_is_less( version: vers, test_version: "7.0.21" )){
		fix = "7.0.21";
	}
}
else {
	if(IsMatchRegexp( vers, "^7\\.1" )){
		if(version_is_less( version: vers, test_version: "7.1.7" )){
			fix = "7.1.7";
		}
	}
}
if(fix){
	report = report_fixed_ver( installed_version: vers, fixed_version: fix );
	security_message( port: phpport, data: report );
	exit( 0 );
}
exit( 99 );

