CPE = "cpe:/a:php:php";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.808791" );
	script_version( "2021-08-10T15:24:26+0000" );
	script_cve_id( "CVE-2016-5096", "CVE-2016-5094", "CVE-2016-5095" );
	script_bugtraq_id( 90861, 90857, 92144 );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2021-08-10 15:24:26 +0000 (Tue, 10 Aug 2021)" );
	script_tag( name: "creation_date", value: "2016-08-17 12:42:53 +0530 (Wed, 17 Aug 2016)" );
	script_name( "PHP Multiple Vulnerabilities - 03 - Aug16 (Windows)" );
	script_tag( name: "summary", value: "PHP is prone to multiple vulnerabilities." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "Multiple flaws are due to:

  - An integer overflow in the fread function in 'ext/standard/file.c' script.

  - An integer overflow in the php_html_entities function in
    'ext/standard/html.c' script.

  - An Integer overflow in the php_escape_html_entities_ex function in
    'ext/standard/html.c' script." );
	script_tag( name: "impact", value: "Successfully exploiting this issue allow
  remote attackers to cause a denial of service or possibly have unspecified
  other impact." );
	script_tag( name: "affected", value: "PHP versions prior to 5.5.36 and 5.6.x
  before 5.6.22 on Windows" );
	script_tag( name: "solution", value: "Update to PHP version 5.5.36, or 5.6.22,
  or later." );
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
if( version_is_less( version: phpVer, test_version: "5.5.36" ) ){
	fix = "5.5.36";
	VULN = TRUE;
}
else {
	if(IsMatchRegexp( phpVer, "^5\\.6" )){
		if(version_in_range( version: phpVer, test_version: "5.6.0", test_version2: "5.6.21" )){
			fix = "5.6.22";
			VULN = TRUE;
		}
	}
}
if(VULN){
	report = report_fixed_ver( installed_version: phpVer, fixed_version: fix );
	security_message( data: report, port: phpPort );
	exit( 0 );
}
exit( 99 );

