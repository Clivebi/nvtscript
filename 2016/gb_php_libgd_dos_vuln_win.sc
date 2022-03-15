CPE = "cpe:/a:php:php";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.809337" );
	script_version( "2021-09-20T12:38:59+0000" );
	script_cve_id( "CVE-2016-7568" );
	script_bugtraq_id( 93184 );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2021-09-20 12:38:59 +0000 (Mon, 20 Sep 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-03-07 20:00:00 +0000 (Thu, 07 Mar 2019)" );
	script_tag( name: "creation_date", value: "2016-10-03 12:09:46 +0530 (Mon, 03 Oct 2016)" );
	script_name( "PHP 'libgd' Denial of Service Vulnerability (Windows)" );
	script_tag( name: "summary", value: "PHP is prone to a denial of service (DoS) vulnerability." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "The flaw exists due to an integer overflow
  in the gdImageWebpCtx function in gd_webp.c in the GD Graphics Library." );
	script_tag( name: "impact", value: "Successfully exploiting this issue allow
  remote attackers to cause a denial of service, or possibly have unspecified
  other impact." );
	script_tag( name: "affected", value: "PHP versions 5.x through 5.6.26 and 7.0.x through 7.0.11 on Windows" );
	script_tag( name: "solution", value: "Update to PHP version 5.6.27 or 7.0.12." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_xref( name: "URL", value: "http://www.php.net/ChangeLog-5.php" );
	script_xref( name: "URL", value: "http://www.php.net/ChangeLog-7.php" );
	script_xref( name: "URL", value: "http://seclists.org/oss-sec/2016/q3/639" );
	script_xref( name: "URL", value: "https://bugs.php.net/bug.php?id=73003" );
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
if(version_is_less_equal( version: phpVer, test_version: "5.6.26" ) || version_in_range( version: phpVer, test_version: "7.0", test_version2: "7.0.11" )){
	report = report_fixed_ver( installed_version: phpVer, fixed_version: "5.6.27/7.0.12" );
	security_message( data: report, port: phpPort );
	exit( 0 );
}
exit( 99 );

