CPE = "cpe:/a:php:php";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.143544" );
	script_version( "2021-07-08T11:00:45+0000" );
	script_tag( name: "last_modification", value: "2021-07-08 11:00:45 +0000 (Thu, 08 Jul 2021)" );
	script_tag( name: "creation_date", value: "2020-02-21 03:00:09 +0000 (Fri, 21 Feb 2020)" );
	script_tag( name: "cvss_base", value: "6.4" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:N/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-03-26 15:15:00 +0000 (Thu, 26 Mar 2020)" );
	script_cve_id( "CVE-2020-7061", "CVE-2020-7062", "CVE-2020-7063" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_name( "PHP 7.3.x < 7.3.15, 7.4.x < 7.4.3 Multiple Vulnerabilities - Feb20 (Windows)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "secpod_php_smb_login_detect.sc", "gb_php_http_detect.sc", "os_detection.sc" );
	script_mandatory_keys( "php/detected", "Host/runs_windows" );
	script_tag( name: "summary", value: "PHP is prone to multiple vulnerabilities." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "PHP is prone to multiple vulnerabilities:

  - Heap-buffer-overflow in phar_extract_file (CVE-2020-7061)

  - Null Pointer Dereference in PHP Session Upload Progress (CVE-2020-7062)

  - Files added to tar with Phar::buildFromIterator have all-access permissions (CVE-2020-7063)" );
	script_tag( name: "affected", value: "PHP versions 7.3.x and 7.4.x." );
	script_tag( name: "solution", value: "Update to version 7.3.15, 7.4.3 or later." );
	script_xref( name: "URL", value: "https://www.php.net/ChangeLog-7.php#7.3.15" );
	script_xref( name: "URL", value: "https://www.php.net/ChangeLog-7.php#7.4.3" );
	exit( 0 );
}
require("host_details.inc.sc");
require("version_func.inc.sc");
if(isnull( port = get_app_port( cpe: CPE ) )){
	exit( 0 );
}
if(!infos = get_app_version_and_location( cpe: CPE, port: port, exit_no_version: TRUE )){
	exit( 0 );
}
version = infos["version"];
location = infos["location"];
if(version_in_range( version: version, test_version: "7.3.0", test_version2: "7.3.14" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "7.3.15", install_path: location );
	security_message( port: port, data: report );
	exit( 0 );
}
if(version_in_range( version: version, test_version: "7.4.0", test_version2: "7.4.2" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "7.4.3", install_path: location );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

