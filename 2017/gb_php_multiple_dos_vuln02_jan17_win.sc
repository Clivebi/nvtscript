CPE = "cpe:/a:php:php";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.108055" );
	script_version( "2021-09-15T08:01:41+0000" );
	script_cve_id( "CVE-2016-10159", "CVE-2016-10160" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2021-09-15 08:01:41 +0000 (Wed, 15 Sep 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2018-05-04 01:29:00 +0000 (Fri, 04 May 2018)" );
	script_tag( name: "creation_date", value: "2017-01-25 11:00:00 +0100 (Wed, 25 Jan 2017)" );
	script_name( "PHP Multiple Denial of Service Vulnerabilities - 02 - Jan17 (Windows)" );
	script_copyright( "Copyright (C) 2017 Greenbone Networks GmbH" );
	script_category( ACT_GATHER_INFO );
	script_family( "Denial of Service" );
	script_dependencies( "secpod_php_smb_login_detect.sc", "gb_php_http_detect.sc", "os_detection.sc" );
	script_mandatory_keys( "php/detected", "Host/runs_windows" );
	script_xref( name: "URL", value: "http://www.php.net/ChangeLog-5.php" );
	script_xref( name: "URL", value: "http://www.php.net/ChangeLog-7.php" );
	script_tag( name: "summary", value: "PHP is prone to multiple denial of service (DoS) vulnerabilities." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "Multiple flaws are due to

  - A integer overflow in the phar_parse_pharfile function in ext/phar/phar.c
  via a truncated manifest entry in a PHAR archive.

  - A off-by-one error in the phar_parse_pharfile function in ext/phar/phar.c
  via a crafted PHAR archive with an alias mismatch." );
	script_tag( name: "impact", value: "Successfully exploiting this issue allow
  remote attackers to cause a denial of service (memory consumption or application crash)." );
	script_tag( name: "affected", value: "PHP versions before 5.6.30 and 7.0.x before 7.0.15" );
	script_tag( name: "solution", value: "Update to PHP version 5.6.30, 7.0.15 or later." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "remote_banner" );
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
if(version_is_less( version: vers, test_version: "5.6.30" )){
	vuln = TRUE;
	fix = "5.6.30";
}
if(version_in_range( version: vers, test_version: "7.0", test_version2: "7.0.14" )){
	vuln = TRUE;
	fix = "7.0.15";
}
if(vuln){
	report = report_fixed_ver( installed_version: vers, fixed_version: fix );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

