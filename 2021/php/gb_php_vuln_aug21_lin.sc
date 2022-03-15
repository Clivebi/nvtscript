CPE = "cpe:/a:php:php";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.146584" );
	script_version( "2021-08-27T08:15:01+0000" );
	script_tag( name: "last_modification", value: "2021-08-27 08:15:01 +0000 (Fri, 27 Aug 2021)" );
	script_tag( name: "creation_date", value: "2021-08-27 08:02:30 +0000 (Fri, 27 Aug 2021)" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:N/A:N" );
	script_tag( name: "qod_type", value: "remote_banner_unreliable" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_name( "PHP < 7.3.30, 7.4.x < 7.4.23, 8.0.x < 8.0.10 Security Update (Aug 2021) - Linux" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "gb_php_ssh_login_detect.sc", "gb_php_http_detect.sc", "os_detection.sc" );
	script_mandatory_keys( "php/detected", "Host/runs_unixoide" );
	script_tag( name: "summary", value: "PHP released new versions which include security fixes." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "affected", value: "PHP versions prior to 7.3.30, 7.4.x through 7.4.22 and 8.0.x
  through 8.0.9." );
	script_tag( name: "solution", value: "Update to version 7.3.30, 7.4.23, 8.0.10 or later." );
	script_xref( name: "URL", value: "https://www.php.net/ChangeLog-7.php#7.3.30" );
	script_xref( name: "URL", value: "https://www.php.net/ChangeLog-7.php#7.4.23" );
	script_xref( name: "URL", value: "https://www.php.net/ChangeLog-8.php#8.0.10" );
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
if(version_is_less( version: version, test_version: "7.3.30" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "7.3.30", install_path: location );
	security_message( port: port, data: report );
	exit( 0 );
}
if(version_in_range( version: version, test_version: "7.4", test_version2: "7.4.22" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "7.4.23", install_path: location );
	security_message( port: port, data: report );
	exit( 0 );
}
if(version_in_range( version: version, test_version: "8.0", test_version2: "8.0.9" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "8.0.10", install_path: location );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

