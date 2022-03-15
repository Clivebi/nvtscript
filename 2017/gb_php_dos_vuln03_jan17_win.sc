CPE = "cpe:/a:php:php";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.108057" );
	script_version( "2021-09-14T11:01:46+0000" );
	script_cve_id( "CVE-2016-10162" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:P" );
	script_tag( name: "last_modification", value: "2021-09-14 11:01:46 +0000 (Tue, 14 Sep 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2018-05-04 01:29:00 +0000 (Fri, 04 May 2018)" );
	script_tag( name: "creation_date", value: "2017-01-25 11:00:00 +0100 (Wed, 25 Jan 2017)" );
	script_name( "PHP Denial of Service Vulnerability - 03 - Jan17 (Windows)" );
	script_copyright( "Copyright (C) 2017 Greenbone Networks GmbH" );
	script_category( ACT_GATHER_INFO );
	script_family( "Denial of Service" );
	script_dependencies( "secpod_php_smb_login_detect.sc", "gb_php_http_detect.sc", "os_detection.sc" );
	script_mandatory_keys( "php/detected", "Host/runs_windows" );
	script_xref( name: "URL", value: "http://www.php.net/ChangeLog-7.php" );
	script_tag( name: "summary", value: "PHP is prone to multiple denial of service (DoS) vulnerabilities." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "The flaw exists due to the php_wddx_pop_element
  function in ext/wddx/wddx.c via an inapplicable class name in a wddxPacket XML document,
  leading to mishandling in a wddx_deserialize call." );
	script_tag( name: "impact", value: "Successfully exploiting this issue allow
  remote attackers to cause a denial of service (NULL pointer dereference
  and application crash)." );
	script_tag( name: "affected", value: "PHP versions 7.0.x before 7.0.15 and 7.1.x before 7.1.1." );
	script_tag( name: "solution", value: "Update to PHP version 7.0.15, 7.1.1
  or later." );
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
if(version_in_range( version: vers, test_version: "7.0", test_version2: "7.0.14" )){
	vuln = TRUE;
	fix = "7.0.15";
}
if(IsMatchRegexp( vers, "^7\\.1" )){
	if(version_is_less( version: vers, test_version: "7.1.1" )){
		vuln = TRUE;
		fix = "7.1.1";
	}
}
if(vuln){
	report = report_fixed_ver( installed_version: vers, fixed_version: fix );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

