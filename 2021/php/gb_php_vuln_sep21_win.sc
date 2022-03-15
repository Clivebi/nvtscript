CPE = "cpe:/a:php:php";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.117695" );
	script_version( "2021-09-27T06:13:32+0000" );
	script_tag( name: "last_modification", value: "2021-09-27 06:13:32 +0000 (Mon, 27 Sep 2021)" );
	script_tag( name: "creation_date", value: "2021-09-27 05:54:48 +0000 (Mon, 27 Sep 2021)" );
	script_tag( name: "cvss_base", value: "4.9" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:L/Au:N/C:N/I:N/A:C" );
	script_cve_id( "CVE-2021-21706" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_name( "PHP < 7.3.30, 7.4.x < 7.4.23, 8.0.x < 8.0.10 Security Update (Sep 2021) - Windows" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "gb_php_ssh_login_detect.sc", "gb_php_http_detect.sc", "os_detection.sc" );
	script_mandatory_keys( "php/detected", "Host/runs_windows" );
	script_tag( name: "summary", value: "PHP released new versions which includes a security fix." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "Fixed bug #81420 (ZipArchive::extractTo extracts outside of
  destination)." );
	script_tag( name: "affected", value: "PHP versions prior to 7.3.31, 7.4.x through 7.4.23 and 8.0.x
  through 8.0.10." );
	script_tag( name: "solution", value: "Update to version 7.3.31, 7.4.24, 8.0.11 or later." );
	script_xref( name: "URL", value: "https://www.php.net/ChangeLog-7.php#7.3.31" );
	script_xref( name: "URL", value: "https://www.php.net/ChangeLog-7.php#7.4.24" );
	script_xref( name: "URL", value: "https://www.php.net/ChangeLog-8.php#8.0.11" );
	script_xref( name: "URL", value: "http://bugs.php.net/81420" );
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
if(version_is_less( version: version, test_version: "7.3.31" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "7.3.31", install_path: location );
	security_message( port: port, data: report );
	exit( 0 );
}
if(version_in_range( version: version, test_version: "7.4", test_version2: "7.4.23" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "7.4.24", install_path: location );
	security_message( port: port, data: report );
	exit( 0 );
}
if(version_in_range( version: version, test_version: "8.0", test_version2: "8.0.10" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "8.0.11", install_path: location );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

