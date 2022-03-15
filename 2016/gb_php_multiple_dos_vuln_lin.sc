CPE = "cpe:/a:php:php";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.808611" );
	script_version( "2021-09-20T08:01:57+0000" );
	script_cve_id( "CVE-2015-8877", "CVE-2015-8879", "CVE-2015-8874" );
	script_bugtraq_id( 90866, 90842, 90714 );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:P" );
	script_tag( name: "last_modification", value: "2021-09-20 08:01:57 +0000 (Mon, 20 Sep 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2018-01-05 02:30:00 +0000 (Fri, 05 Jan 2018)" );
	script_tag( name: "creation_date", value: "2016-07-14 12:14:00 +0530 (Thu, 14 Jul 2016)" );
	script_name( "PHP Multiple Denial of Service Vulnerabilities (Linux)" );
	script_tag( name: "summary", value: "PHP is prone to multiple denial of service (DoS) vulnerabilities." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "Multiple flaws are due to

  - An improper handling of driver behavior for SQL_WVARCHAR columns in the
    'odbc_bindcols function' in 'ext/odbc/php_odbc.c' script.

  - The 'gdImageScaleTwoPass' function in gd_interpolation.c script in the
    GD Graphics Library uses inconsistent allocate and free approaches." );
	script_tag( name: "impact", value: "Successfully exploiting this issue allow
  remote attackers to cause a denial of service (application crash or
  memory consuption)." );
	script_tag( name: "affected", value: "PHP versions prior to 5.6.12 on Linux" );
	script_tag( name: "solution", value: "Update to PHP version 5.6.12
  or later." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "remote_banner_unreliable" );
	script_xref( name: "URL", value: "http://www.php.net/ChangeLog-5.php" );
	script_copyright( "Copyright (C) 2016 Greenbone Networks GmbH" );
	script_category( ACT_GATHER_INFO );
	script_family( "Denial of Service" );
	script_dependencies( "gb_php_ssh_login_detect.sc", "gb_php_http_detect.sc", "os_detection.sc" );
	script_mandatory_keys( "php/detected", "Host/runs_unixoide" );
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
if(version_is_less( version: phpVer, test_version: "5.6.12" )){
	report = report_fixed_ver( installed_version: phpVer, fixed_version: "5.6.12" );
	security_message( data: report, port: phpPort );
	exit( 0 );
}
exit( 99 );

